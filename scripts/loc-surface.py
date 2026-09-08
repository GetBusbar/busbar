#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Measure the plugin-visible SURFACE of a crate, in lines.

The surface is what a reader of the crate has to hold in their head to use it:
non-blank, non-comment code lines under the crate's `src/`. It deliberately
excludes the things that are proofs rather than surface --- test modules
(`#[cfg(test)] mod ...`), the `src/tests/**` tree, and the tests, fixtures and
data tables that live outside `src/` entirely.

Counting rule, per `.rs` file under `<crate>/src/`:

  * `src/tests.rs` and everything under `src/tests/` is skipped outright.
  * Block comments (`/* ... */`, nested) are removed.
  * Line comments (`//`, `///`, `//!`) are removed.
  * String and char literal bodies are blanked, so braces and comment
    markers inside them cannot confuse the scanner.
  * A `#[cfg(test)]` (or `#[cfg(all(test, ...))]`) attribute and the item it
    guards are removed, whether that item is an inline `mod x { ... }` or a
    file-backed `mod x;`.
  * What is left, minus blank/whitespace-only lines, is the surface.

Usage:

    scripts/loc-surface.py                       # every crate under crates/
    scripts/loc-surface.py crates/busbar-caps    # named crates only
    scripts/loc-surface.py --per-file
    scripts/loc-surface.py --ceiling busbar-contract,busbar-caps=3000

`--ceiling <crate>[,<crate>...]=<n>` asserts that the summed surface of the
listed crates is at most `n`; it may be repeated. Any breach exits non-zero.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

CFG_TEST = re.compile(r"#\[\s*cfg\s*\(.*\btest\b.*\)\s*\]")


def strip_comments_and_literals(text: str) -> str:
    """Return `text` with comments removed and literal bodies blanked.

    Newlines are preserved so the result stays line-addressable.
    """
    out: list[str] = []
    i = 0
    n = len(text)
    block_depth = 0
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if block_depth:
            if ch == "/" and nxt == "*":
                block_depth += 1
                i += 2
                continue
            if ch == "*" and nxt == "/":
                block_depth -= 1
                i += 2
                continue
            if ch == "\n":
                out.append("\n")
            i += 1
            continue

        if ch == "/" and nxt == "*":
            block_depth = 1
            i += 2
            continue

        if ch == "/" and nxt == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue

        if ch == "r" and text.startswith("r", i):
            # raw string: r"..." or r#"..."#
            j = i + 1
            hashes = 0
            while j < n and text[j] == "#":
                hashes += 1
                j += 1
            if j < n and text[j] == '"':
                terminator = '"' + "#" * hashes
                end = text.find(terminator, j + 1)
                if end == -1:
                    end = n
                    body = text[j + 1 : end]
                    i = n
                else:
                    body = text[j + 1 : end]
                    i = end + len(terminator)
                out.append('""')
                out.append("\n" * body.count("\n"))
                continue

        if ch == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    break
                j += 1
            body = text[i + 1 : min(j, n)]
            out.append('""')
            out.append("\n" * body.count("\n"))
            i = min(j + 1, n)
            continue

        if ch == "'":
            # A char literal, or a lifetime. Lifetimes have no closing quote.
            m = re.match(r"'(?:\\.|[^\\'])'", text[i:])
            if m:
                out.append("' '")
                i += m.end()
                continue

        out.append(ch)
        i += 1

    return "".join(out)


def drop_cfg_test_items(lines: list[str]) -> list[str]:
    """Drop every `#[cfg(test)]`-guarded item from `lines`.

    THE ATTRIBUTE AND ITS ITEM MAY SHARE A LINE. This used to drop the whole matching line and
    then start hunting for the guarded item on the NEXT one --- so `#[cfg(test)] mod t { ... }`
    written on one line dropped that line AND ate the following real item as if it were the thing
    the attribute guarded. The surface then reads LOW, and low is the direction that makes a
    `--ceiling` pass: a crate genuinely over its limit measures under it because a one-line test
    module sat above the code that pushed it over. So the scan for the item's end starts at the
    tail of the attribute's own line.
    """
    kept: list[str] = []
    i = 0
    n = len(lines)
    while i < n:
        m = CFG_TEST.search(lines[i])
        if not m:
            kept.append(lines[i])
            i += 1
            continue

        depth = 0
        opened = False

        def consume(line: str) -> bool:
            """Advance the counters over `line`; True once the guarded item has ended."""
            nonlocal depth, opened
            for ch in line:
                if ch == "{":
                    depth += 1
                    opened = True
                elif ch == "}":
                    depth -= 1
            if opened and depth <= 0:
                return True
            return not opened and ";" in line

        # Whatever follows the attribute ON ITS OWN LINE is the first of the item's text.
        rest = lines[i][m.end():]
        i += 1
        if rest.strip() and consume(rest):
            continue
        # Otherwise: any further attributes, then the guarded item, on the lines below.
        while i < n:
            line = lines[i]
            i += 1
            if consume(line):
                break
    return kept


def surface_lines(path: Path) -> int:
    text = path.read_text(encoding="utf-8", errors="replace")
    stripped = strip_comments_and_literals(text)
    lines = drop_cfg_test_items(stripped.split("\n"))
    return sum(1 for line in lines if line.strip())


def is_proof_path(rel: Path) -> bool:
    # A `tests` directory is proofs wherever it sits, not only directly under `src/`. The tree keeps
    # a module's tests BESIDE the module (`src/config/tests/`, `src/plane/tests/`, …), and reading
    # only the top-level `src/tests/` counted every one of those nested trees as SURFACE — so a
    # ceiling measured a crate's proofs along with its product and a crate could breach its budget by
    # writing tests. Match the `tests` COMPONENT at any depth, which is the rule the docstring above
    # has always stated and the same rule the purity lints already apply.
    parts = rel.parts
    if "tests" in parts[:-1]:
        return True
    # `tests.rs` — Rust's `#[cfg(test)] mod tests;` file convention — is proofs at any depth too, for
    # exactly the same reason.
    return rel.name == "tests.rs"


def measure_crate(crate_dir: Path) -> tuple[int, list[tuple[str, int]]]:
    src = crate_dir / "src"
    per_file: list[tuple[str, int]] = []
    total = 0
    for path in sorted(src.rglob("*.rs")):
        rel = path.relative_to(src)
        if is_proof_path(rel):
            continue
        count = surface_lines(path)
        per_file.append((str(rel), count))
        total += count
    return total, per_file


def repo_root() -> Path:
    here = Path(__file__).resolve().parent
    return here.parent


def parse_ceiling(spec: str) -> tuple[list[str], int]:
    if "=" not in spec:
        raise argparse.ArgumentTypeError(
            f"--ceiling wants <crate>[,<crate>...]=<n>, got {spec!r}"
        )
    names, _, limit = spec.rpartition("=")
    try:
        value = int(limit)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not a line count: {limit!r}") from exc
    crates = [name.strip() for name in names.split(",") if name.strip()]
    if not crates:
        raise argparse.ArgumentTypeError(f"--ceiling names no crate: {spec!r}")
    return crates, value


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Measure the plugin-visible surface (code lines under src/) per crate."
    )
    parser.add_argument(
        "crates",
        nargs="*",
        help="crate directories to measure; default is every crate under crates/",
    )
    parser.add_argument(
        "--ceiling",
        action="append",
        default=[],
        metavar="CRATES=N",
        help="assert the summed surface of CRATES is at most N; repeatable",
    )
    parser.add_argument(
        "--per-file", action="store_true", help="also print a per-file breakdown"
    )
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="prove the counting rules and the ceiling on fixtures of known surface, then exit",
    )
    args = parser.parse_args(argv)

    if args.selftest:
        return selftest()

    root = repo_root()
    ceilings = [parse_ceiling(spec) for spec in args.ceiling]

    if args.crates:
        crate_dirs = [Path(c) if Path(c).is_absolute() else root / c for c in args.crates]
    else:
        named = {name for crates, _ in ceilings for name in crates}
        crate_dirs = sorted(
            p for p in (root / "crates").iterdir() if (p / "src").is_dir()
        )
        if named:
            crate_dirs = [p for p in crate_dirs if p.name in named]

    results: dict[str, int] = {}
    per_file: dict[str, list[tuple[str, int]]] = {}
    for crate_dir in crate_dirs:
        if not (crate_dir / "src").is_dir():
            print(f"loc-surface: no src/ under {crate_dir}", file=sys.stderr)
            return 2
        total, files = measure_crate(crate_dir)
        results[crate_dir.name] = total
        per_file[crate_dir.name] = files

    width = max((len(name) for name in results), default=10)
    width = max(width, len("crate"))
    print(f"{'crate':<{width}}  surface")
    print(f"{'-' * width}  -------")
    for name in sorted(results):
        print(f"{name:<{width}}  {results[name]:>7}")
        if args.per_file:
            for rel, count in per_file[name]:
                print(f"  {rel:<{width}}  {count:>7}")
    print(f"{'-' * width}  -------")
    print(f"{'total':<{width}}  {sum(results.values()):>7}")

    failed = False
    for crates, limit in ceilings:
        missing = [name for name in crates if name not in results]
        if missing:
            print(
                f"loc-surface: --ceiling names crates that were not measured: "
                f"{', '.join(missing)}",
                file=sys.stderr,
            )
            return 2
        total = sum(results[name] for name in crates)
        label = "+".join(crates)
        # ── A CRATE THAT MEASURED NOTHING IS UNDER EVERY CEILING ──────────────────────────────────
        # `total <= limit` is satisfied by 0, and 0 is what this script reports for a `src/` that
        # holds no `.rs` at all: a crate whose sources moved into a subcrate, a rename that left
        # the ceiling naming the old shell, a build layout that put the code somewhere `rglob`
        # does not reach. Each of those prints `ok <crate> 0 <= 3000` -- a ceiling honoured by a
        # crate nobody measured, which is the same green as a crate that is genuinely small.
        # A ceiling is a statement about code; there has to be some.
        empty = [name for name in crates if results[name] == 0]
        if empty:
            print(
                f"FAIL  {label}  measured 0 surface lines in: {', '.join(empty)}. A crate with no "
                f"code is under every ceiling, so this is not a pass -- point the ceiling at where "
                f"the code went."
            )
            failed = True
        elif total > limit:
            print(f"FAIL  {label}  {total} > {limit}")
            failed = True
        else:
            print(f"ok    {label}  {total} <= {limit}")

    return 1 if failed else 0


# ── SELF-TEST — a measurement nothing has watched be wrong is a number, not a measurement ─────────
# Drives the REAL strip/drop/measure path over fixture crates whose surface is known by hand, and
# the REAL main() over a ceiling that must be refused. Without this, every rule below was one edit
# from silently under-counting, and under-counting is the direction a ceiling forgives.
SELFTEST_FIXTURES = {
    "plain": (
        "pub fn one() -> u32 { 1 }\n"
        "pub fn two() -> u32 { 2 }\n",
        2,
        "two code lines are two",
    ),
    "blank-and-comments": (
        "// a line comment\n"
        "\n"
        "/// a doc comment\n"
        "/* a block\n"
        "   comment */\n"
        "pub fn one() -> u32 { 1 }\n",
        1,
        "comments and blanks are not surface",
    ),
    "inline-cfg-test": (
        "#[cfg(test)] mod t { fn a() {} }\n"
        "pub fn one() -> u32 { 1 }\n"
        "pub fn two() -> u32 { 2 }\n",
        2,
        "an attribute and its item on ONE line do not also eat the next item",
    ),
    "block-cfg-test": (
        "#[cfg(test)]\n"
        "mod t {\n"
        "    fn a() {}\n"
        "}\n"
        "pub fn one() -> u32 { 1 }\n",
        1,
        "a multi-line cfg(test) module is dropped, and only it",
    ),
    "file-backed-cfg-test": (
        "#[cfg(test)]\n"
        "mod t;\n"
        "pub fn one() -> u32 { 1 }\n",
        1,
        "a file-backed `mod t;` under cfg(test) is dropped at its semicolon",
    ),
    "braces-in-literals": (
        'pub const A: &str = "{ } // not a comment";\n'
        "pub const B: char = '}';\n"
        "pub fn one() -> u32 { 1 }\n",
        3,
        "braces and comment markers inside literals do not shift the depth",
    ),
    "cfg-all-test": (
        '#[cfg(all(test, feature = "x"))]\n'
        "mod t {\n"
        "    fn a() {}\n"
        "}\n"
        "pub fn one() -> u32 { 1 }\n",
        1,
        "`cfg(all(test, ...))` guards the same way a bare `cfg(test)` does",
    ),
}


def selftest() -> int:
    import tempfile

    print("== loc-surface SELF-TEST ==")
    bad = 0

    def say(ok: bool, msg: str) -> None:
        nonlocal bad
        print(("PASS  " if ok else "FAIL  ") + msg)
        if not ok:
            bad += 1

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        for name, (body, want, why) in SELFTEST_FIXTURES.items():
            path = root / f"{name}.rs"
            path.write_text(body, encoding="utf-8")
            got = surface_lines(path)
            say(got == want, f"{why} (wanted {want}, measured {got})")

        # `src/tests.rs` and `src/tests/**` are proofs, not surface, and are never counted.
        crate = root / "crate" / "src"
        (crate / "tests").mkdir(parents=True)
        (crate / "lib.rs").write_text("pub fn one() -> u32 { 1 }\n", encoding="utf-8")
        (crate / "tests.rs").write_text("fn t1() {}\nfn t2() {}\n", encoding="utf-8")
        (crate / "tests" / "more.rs").write_text("fn t3() {}\n", encoding="utf-8")
        # A NESTED tests tree and a nested `tests.rs` are proofs too — the shape this tree actually
        # uses (a module's tests beside the module). Counting them as surface let a crate breach its
        # own ceiling by writing tests, which is the opposite of what a ceiling is for.
        (crate / "config" / "tests").mkdir(parents=True)
        (crate / "config" / "mod.rs").write_text("pub fn two() -> u32 { 2 }\n", encoding="utf-8")
        (crate / "config" / "tests.rs").write_text("fn t4() {}\n", encoding="utf-8")
        (crate / "config" / "tests" / "deep.rs").write_text("fn t5() {}\nfn t6() {}\n", encoding="utf-8")
        total, per_file = measure_crate(root / "crate")
        say(total == 2, f"the tests tree is not surface (wanted 2, measured {total})")
        say(
            sorted(rel for rel, _ in per_file) == ["config/mod.rs", "lib.rs"],
            f"only the production files are measured (measured {[rel for rel, _ in per_file]})",
        )

        # THE CEILING ITSELF, through the real main(): a crate over its limit is refused, the same
        # crate under it is accepted, and a crate that measured NOTHING is refused rather than
        # waved through for being under every limit.
        crates_dir = root / "crates"
        for name, body in (
            ("big", "pub fn a() {}\npub fn b() {}\npub fn c() {}\n"),
            ("small", "pub fn a() {}\n"),
        ):
            (crates_dir / name / "src").mkdir(parents=True)
            (crates_dir / name / "src" / "lib.rs").write_text(body, encoding="utf-8")
        (crates_dir / "hollow" / "src").mkdir(parents=True)

        def run(args: list[str]) -> int:
            import contextlib
            import io

            global repo_root
            saved, repo_root = repo_root, lambda: root
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    return main(args)
            finally:
                repo_root = saved

        say(run(["--ceiling", "big=2"]) == 1, "a crate OVER its ceiling is refused")
        say(run(["--ceiling", "big=3"]) == 0, "the same crate AT its ceiling is accepted")
        say(
            run(["--ceiling", "hollow=3000"]) == 1,
            "a crate whose src/ holds no .rs is REFUSED, not reported under every ceiling",
        )
        say(
            run(["--ceiling", "big,small=4"]) == 0
            and run(["--ceiling", "big,small=3"]) == 1,
            "a summed ceiling over two crates bites at the sum",
        )
        say(run(["--ceiling", "no-such-crate=10"]) == 2, "a ceiling naming no measured crate is refused")

    print()
    if bad:
        print(f"loc-surface selftest: RED ({bad} case(s) failed)")
        return 1
    print("loc-surface selftest: GREEN")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
