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
    """Drop every `#[cfg(test)]`-guarded item from `lines`."""
    kept: list[str] = []
    i = 0
    n = len(lines)
    while i < n:
        if not CFG_TEST.search(lines[i]):
            kept.append(lines[i])
            i += 1
            continue

        # Skip the attribute, any further attributes, then the guarded item.
        i += 1
        depth = 0
        opened = False
        while i < n:
            line = lines[i]
            i += 1
            for ch in line:
                if ch == "{":
                    depth += 1
                    opened = True
                elif ch == "}":
                    depth -= 1
            if opened and depth <= 0:
                break
            if not opened and ";" in line:
                break
    return kept


def surface_lines(path: Path) -> int:
    text = path.read_text(encoding="utf-8", errors="replace")
    stripped = strip_comments_and_literals(text)
    lines = drop_cfg_test_items(stripped.split("\n"))
    return sum(1 for line in lines if line.strip())


def is_proof_path(rel: Path) -> bool:
    parts = rel.parts
    if parts[0] == "tests":
        return True
    return len(parts) == 1 and rel.name == "tests.rs"


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
    args = parser.parse_args(argv)

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
        if total > limit:
            print(f"FAIL  {label}  {total} > {limit}")
            failed = True
        else:
            print(f"ok    {label}  {total} <= {limit}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
