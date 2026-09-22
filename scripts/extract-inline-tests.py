# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# extract-inline-tests.py -- the worker behind scripts/extract-inline-tests.sh.
#
# THE OWNER'S RULING: "all tests are in `_tests.rs` for easy ignoring". A `#[cfg(test)] mod tests
# { ... }` block written INLINE in a production file breaks that: the file's real production size
# becomes unmeasurable without a bespoke script, and "how big is 1.6.0 next to 1.5.5" stops being a
# question anybody can answer.
#
# This moves such a block out, BYTE-IDENTICALLY, to the tree's existing convention (see the
# `--help` of the shell entrypoint for the shape), and REFUSES every file it cannot transform
# safely rather than guessing.
#
# WHY A REAL LEXER AND NOT A REGEX. The obvious measurement -- "lines from the first `#[cfg(test)]`
# to EOF" -- is wrong in both directions and was the figure this work started from. It counts the
# whole tail of `crates/busbar-transport-http/src/lib.rs` (1,531 lines) as inline test code because
# ONE `#[cfg(test)] pub(crate) async fn scratch_addr` sits at line 309 inside an `impl`, while the
# file's actual test module is the compliant `#[cfg(test)] mod tests;` on its last line. A brace
# counter that cannot see `r#"..."#` mis-attributes in the other direction: a `}` inside a raw
# string closes the test module early and re-files every line after it as production. So the scan
# masks comments and string literals -- preserving length, so every offset still points at the
# original byte -- and matches braces on the mask.

import argparse
import os
import re
import sys

# ── the lexer ────────────────────────────────────────────────────────────────────────────────────

_RAW_OPEN = re.compile(rb'(?:b?r)(#*)"')


def mask(src: bytes):
    """A same-length copy of `src` with comment bodies and string/char literal bodies blanked to
    spaces (newlines kept, so line numbers and offsets are preserved), plus the set of line indices
    that BEGIN inside a multi-line string literal.

    Blanking preserves length so every offset computed on the mask indexes the original byte. The
    delimiters themselves are kept, so a literal is still visible as a literal.
    """
    out = bytearray(src)
    n = len(src)
    i = 0
    in_string_lines = set()

    def blank(a, b):
        for k in range(a, b):
            if out[k] != 0x0A:
                out[k] = 0x20

    def lineno(off):
        return src.count(b"\n", 0, off)

    while i < n:
        c = src[i : i + 1]
        # line comment
        if src[i : i + 2] == b"//":
            j = src.find(b"\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
            continue
        # block comment (nested, as Rust's are)
        if src[i : i + 2] == b"/*":
            depth = 0
            j = i
            while j < n:
                if src[j : j + 2] == b"/*":
                    depth += 1
                    j += 2
                elif src[j : j + 2] == b"*/":
                    depth -= 1
                    j += 2
                    if depth == 0:
                        break
                else:
                    j += 1
            blank(i, min(j, n))
            i = j
            continue
        # raw string: r"", r#""#, br#""#  -- closes only on a quote followed by the SAME hash run
        m = _RAW_OPEN.match(src, i)
        if m and (i == 0 or not re.match(rb"[A-Za-z0-9_]", src[i - 1 : i])):
            hashes = m.group(1)
            body = m.end()
            close = src.find(b'"' + hashes, body)
            end = n if close < 0 else close + 1 + len(hashes)
            blank(body, close if close >= 0 else n)
            if src.count(b"\n", i, end):
                for ln in range(lineno(i) + 1, lineno(end) + 1):
                    in_string_lines.add(ln)
            i = end
            continue
        # ordinary string (and byte string)
        if c == b'"' or (src[i : i + 2] == b'b"'):
            start = i + (2 if c == b"b" else 1)
            j = start
            while j < n:
                if src[j : j + 1] == b"\\":
                    j += 2
                    continue
                if src[j : j + 1] == b'"':
                    break
                j += 1
            blank(start, min(j, n))
            end = min(j + 1, n)
            if src.count(b"\n", i, end):
                for ln in range(lineno(i) + 1, lineno(end) + 1):
                    in_string_lines.add(ln)
            i = end
            continue
        # char literal vs lifetime: `'a` is a lifetime, `'a'` and `'\n'` are chars.
        if c == b"'":
            m2 = re.match(rb"'(?:\\.|[^\\'])'", src[i : i + 8])
            if m2:
                blank(i + 1, i + m2.end() - 1)
                i += m2.end()
                continue
            i += 1
            continue
        i += 1

    return bytes(out), in_string_lines


# ── the item scanner ─────────────────────────────────────────────────────────────────────────────

CFG_TEST = re.compile(rb"#\s*\[\s*cfg\s*\(")


def _match_bracket(msk, open_at, opener, closer):
    """Offset just past the bracket matching the one at `open_at`, or None."""
    depth = 0
    i = open_at
    n = len(msk)
    while i < n:
        b = msk[i : i + 1]
        if b == opener:
            depth += 1
        elif b == closer:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


def attributes(src, msk):
    """Every `#[...]` (and `#![...]`) attribute, as (start, end, depth, text)."""
    out = []
    depth = 0
    i = 0
    n = len(msk)
    while i < n:
        b = msk[i : i + 1]
        if b == b"#" and msk[i + 1 : i + 2] in (b"[", b"!"):
            br = i + 1 if msk[i + 1 : i + 2] == b"[" else i + 2
            if msk[br : br + 1] == b"[":
                end = _match_bracket(msk, br, b"[", b"]")
                if end:
                    out.append((i, end, depth, src[i:end]))
                    i = end
                    continue
        if b == b"{":
            depth += 1
        elif b == b"}":
            depth -= 1
        i += 1
    return out


def is_cfg_test(attr_text, msk_text):
    """`#[cfg(test)]` / `#[cfg(all(test, ...))]` -- never `#[cfg(not(test))]`.

    Read on the MASKED text so a `test` inside a string literal in the attribute arms nothing.
    """
    if not CFG_TEST.search(msk_text):
        return False
    body = msk_text[msk_text.find(b"(") :]
    if re.search(rb"not\s*\([^()]*\btest\b", body):
        return False
    return re.search(rb"(^|[^A-Za-z0-9_])test([^A-Za-z0-9_]|$)", body) is not None


class Block:
    """One `#[cfg(test)] mod NAME { ... }` found inline in a production file."""

    def __init__(self, attr_start, item_end, cfg_attr, mod_name, body_start, body_end, vis):
        self.attr_start = attr_start  # first byte of the attribute run
        self.item_end = item_end  # one past the closing `}`
        self.cfg_attr = cfg_attr  # the cfg attribute's own bytes, preserved verbatim
        self.mod_name = mod_name
        self.body_start = body_start  # one past the opening `{`
        self.body_end = body_end  # the closing `}`
        self.vis = vis


class Refusal(Exception):
    pass


def scan(src):
    """(blocks, refusals, support) for one file's bytes.

    * `blocks`   — inline `#[cfg(test)] mod NAME { … }` this tool will move.
    * `refusals` — a block it can SEE but will not move, with the reason. Never a guess.
    * `support`  — `#[cfg(test)]` on a NON-`mod` item (`fn`/`use`/`impl`/`static`/`struct`).
                   These STAY. They are test support that other modules name by path, and moving
                   one would change name resolution. They are reported, not transformed, and they
                   do NOT block the file's real test modules from moving: a sibling `mod tests`
                   reaches them through `use super::*`, which resolves identically once the module
                   is a `#[path]` child of the very same parent.
    """
    msk, in_string = mask(src)
    blocks = []
    refusals = []
    support = []

    attrs = attributes(src, msk)
    consumed = set()
    for idx, (a0, a1, depth, text) in enumerate(attrs):
        if a0 in consumed:
            continue
        if not is_cfg_test(text, msk[a0:a1]):
            continue

        # the whole attribute run this cfg belongs to: contiguous attributes, whitespace only
        # between them. `#[cfg(test)] #[path = "..."] mod tests;` is one item.
        run_start, run_end = a0, a1
        j = idx + 1
        while j < len(attrs):
            b0, b1, _, _ = attrs[j]
            if msk[run_end:b0].strip() == b"":
                consumed.add(b0)
                run_end = b1
                j += 1
            else:
                break
        # and backwards, so the run's first byte is the run's first byte
        k = idx - 1
        while k >= 0:
            b0, b1, _, _ = attrs[k]
            if msk[b1:run_start].strip() == b"":
                consumed.add(b0)
                run_start = b0
                k -= 1
            else:
                break

        line = src.count(b"\n", 0, a0) + 1
        head = msk[run_end:]
        m = re.match(rb"\s*(pub(\s*\([^)]*\))?\s+)?(mod)\s+([A-Za-z_][A-Za-z0-9_]*)\s*([;{])", head)
        if not m:
            snippet = src[run_end : run_end + 60].strip().splitlines()
            snippet = snippet[0].decode("utf8", "replace") if snippet else "?"
            support.append(f"line {line}: `#[cfg(test)]` on `{snippet}` — test support, stays")
            continue
        if m.group(5) == b";":
            continue  # already the convention: `#[cfg(test)] mod x;`
        if depth != 0:
            refusals.append(
                f"line {line}: `#[cfg(test)] mod {m.group(4).decode()}` is nested inside another "
                f"item (brace depth {depth}). The convention's `#[path]` form only resolves at a "
                f"file's top level."
            )
            continue

        open_brace = run_end + m.end() - 1
        close = _match_bracket(msk, open_brace, b"{", b"}")
        if close is None:
            refusals.append(f"line {line}: unbalanced braces after `mod {m.group(4).decode()}`")
            continue

        blocks.append(
            Block(
                attr_start=run_start,
                item_end=close,
                cfg_attr=text,
                mod_name=m.group(4).decode(),
                body_start=open_brace + 1,
                body_end=close - 1,
                vis=(m.group(1) or b"").decode(),
            )
        )

    return blocks, refusals, support, in_string


# ── the transform ────────────────────────────────────────────────────────────────────────────────

def dedent(body: bytes, verbatim: set):
    """The ONE mechanical reformat the convention requires: strip exactly four leading spaces —
    the outer `mod`'s nesting level — from every line of the moved body.

    `verbatim` holds the 0-based indices of body lines that BEGIN INSIDE a multi-line string
    literal. Those bytes are the literal's own content, so they are copied UNTOUCHED: dedenting
    them would silently rewrite a test fixture's expected text. Everything else is code, and code
    at one nesting level dedents by exactly four. Any other non-blank line is a REFUSAL — never a
    guess and never a re-indent.
    """
    lines = body.split(b"\n")
    out = []
    for i, ln in enumerate(lines):
        if i in verbatim:
            out.append(ln)
            continue
        if ln.strip() == b"":
            out.append(b"")
            continue
        if not ln.startswith(b"    "):
            raise Refusal(
                "the body is not uniformly indented one level "
                f"(line `{ln[:60].decode('utf8', 'replace')}`), so the outer-mod unwrap would "
                "have to re-indent rather than unwrap"
            )
        out.append(ln[4:])
    return b"\n".join(out)


def target_name(rel_path, mod_name):
    """Where the moved block lands, by the tree's own convention.

    `src/records.rs`      + `mod tests` -> `src/tests/records_tests.rs`
    `src/v1/service.rs`   + `mod tests` -> `src/v1/tests/service_tests.rs`
    `src/auth/mod.rs`     + `mod tests` -> `src/auth/tests/tests.rs`
    any file + `mod percent_decode_tests` -> `<dir>/tests/percent_decode_tests.rs`
    """
    stem = os.path.splitext(os.path.basename(rel_path))[0]
    if mod_name == "tests":
        leaf = "tests.rs" if stem in ("mod", "lib") else f"{stem}_tests.rs"
    else:
        leaf = f"{mod_name}.rs"
    return os.path.join(os.path.dirname(rel_path), "tests", leaf)


HEADER = (
    b"// SPDX-License-Identifier: Apache-2.0\n"
    b"// Copyright (C) 2026 Busbar Inc and contributors\n"
    b"\n"
)


def plan_file(root, rel):
    """(moves, refusals, support) for one file. A `move` is (target, text, lines, block)."""
    path = os.path.join(root, rel)
    src = open(path, "rb").read()
    blocks, refusals, support, in_string = scan(src)
    if not blocks:
        return [], refusals, support

    moves = []
    seen = {}
    for b in blocks:
        tgt = target_name(rel, b.mod_name)
        if os.path.exists(os.path.join(root, tgt)) or tgt in seen:
            refusals.append(
                f"`mod {b.mod_name}` would land on {tgt}, which already exists — refusing rather "
                f"than merging two test modules into one file"
            )
            continue
        seen[tgt] = True
        body = src[b.body_start : b.body_end]
        # one leading newline (the one after `{`) and the trailing indentation before `}` are the
        # outer mod's punctuation, not the body.
        #
        # `first` is the absolute 0-based index of the body's first line AFTER that newline is
        # dropped, which is what turns `scan`'s absolute in-string line set into body-relative
        # indices for `dedent`.
        first = src.count(b"\n", 0, b.body_start)
        if body.startswith(b"\n"):
            body = body[1:]
            first += 1
        body = body.rstrip(b" \t")
        if body.endswith(b"\n"):
            body = body[:-1]
        verbatim = {ln - first for ln in in_string if ln >= first}
        try:
            body = dedent(body, verbatim)
        except Refusal as e:
            refusals.append(f"`mod {b.mod_name}`: {e}")
            continue
        doc = (
            f"//! Tests for `{rel}`"
            + (f" — the `{b.mod_name}` battery." if b.mod_name != "tests" else ".")
            + "\n\n"
        ).encode()
        moves.append((tgt, HEADER + doc + body.strip(b"\n") + b"\n", body.count(b"\n") + 1, b))

    return moves, refusals, support


def apply_file(root, rel, moves):
    """Rewrite the production file, replacing each block with the convention's declaration."""
    path = os.path.join(root, rel)
    src = open(path, "rb").read()
    for tgt, text, _lines, b in sorted(moves, key=lambda m: -m[3].attr_start):
        decl = (
            b.cfg_attr
            + b"\n"
            + f'#[path = "tests/{os.path.basename(tgt)}"]\n'.encode()
            + f"{b.vis}mod {b.mod_name};".encode()
        )
        src = src[: b.attr_start] + decl + src[b.item_end :]
        out = os.path.join(root, tgt)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "wb") as f:
            f.write(text)
    with open(path, "wb") as f:
        f.write(src)


# ── the walk ─────────────────────────────────────────────────────────────────────────────────────

TEST_FRAGMENTS = ("/tests/", "_tests.rs", "_test.rs", "/tests.rs")


def is_production(rel):
    p = "/" + rel
    return not any(f in p for f in TEST_FRAGMENTS)


def targets(root, paths):
    out = []
    for p in paths:
        ap = os.path.join(root, p)
        if os.path.isfile(ap):
            out.append(os.path.relpath(ap, root).replace(os.sep, "/"))
            continue
        if os.path.isdir(ap) and os.path.isdir(os.path.join(ap, "src")):
            ap = os.path.join(ap, "src")
        for dp, dn, fn in os.walk(ap):
            dn.sort()
            for f in sorted(fn):
                if not f.endswith(".rs"):
                    continue
                rel = os.path.relpath(os.path.join(dp, f), root).replace(os.sep, "/")
                if is_production(rel):
                    out.append(rel)
    return sorted(set(out))


def main():
    ap = argparse.ArgumentParser(
        prog="extract-inline-tests",
        description="Move inline `#[cfg(test)] mod … { … }` blocks to the tree's `tests/` convention.",
    )
    ap.add_argument("paths", nargs="+", help="crate dirs, source dirs or single files")
    ap.add_argument("--apply", action="store_true", help="write (default: report only)")
    ap.add_argument("--support", action="store_true", help="also list the cfg(test) items that STAY")
    ap.add_argument("--root", default=os.path.join(os.path.dirname(__file__), ".."))
    args = ap.parse_args()
    root = os.path.abspath(args.root)

    moved_total = 0
    files_changed = 0
    refused = []
    support_n = 0
    for rel in targets(root, args.paths):
        moves, refusals, support = plan_file(root, rel)
        support_n += len(support)
        if refusals:
            refused.append((rel, refusals))
        if args.support:
            for s in support:
                print(f"  stays   {rel}: {s}")
        if not moves:
            continue
        files_changed += 1
        for tgt, _text, lines, b in moves:
            moved_total += lines
            verb = "MOVE" if args.apply else "would move"
            print(f"{verb} {lines:>5} lines  {rel}  `mod {b.mod_name}`  ->  {tgt}")
        if args.apply:
            apply_file(root, rel, moves)

    if refused:
        print("\nREFUSED (a block this tool can SEE but will not move — each needs a human):")
        for rel, why in refused:
            for w in why:
                print(f"  {rel}: {w}")

    print(
        f"\n{'moved' if args.apply else 'movable'}: {moved_total} lines across "
        f"{files_changed} file(s); refused blocks in {len(refused)} file(s); "
        f"{support_n} cfg(test) non-mod support item(s) left in place"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
