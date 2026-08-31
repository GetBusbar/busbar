#!/usr/bin/env python3
"""One version requirement per external dependency, stated once, in the workspace table.

WHY THIS EXISTS.  `[workspace.dependencies]` makes a single source of truth POSSIBLE; it does not
make it TRUE.  Nothing in Cargo stops a member from writing `serde = "1"` and quietly opening a
second opinion, and nothing stops the workspace table from accumulating entries no member uses.
Before the table existed, `hex`, `sha2` and `tracing` were each declared two different ways and all
three happened to resolve identically -- a property everyone believed, asserted nowhere, checked by
nothing.  Moving that property into a table without a lint would relocate the defect, not remove it.

WHAT IT ASSERTS, on the OUTPUT (the manifests as they actually are):

  1. INHERITANCE   -- every external dependency in every member inherits (`workspace = true`).
                      A literal version string in a member is a failure.
  2. NO ORPHANS    -- every `[workspace.dependencies]` entry is used by at least one member.
                      An unused entry is a version pin nothing obeys.
  3. SET EQUALITY  -- the members this lint inspected are exactly the members the workspace
                      declares.  Neither direction may be short: a manifest that is skipped is a
                      manifest that is unchecked, and a declared member with no manifest is a
                      broken workspace.

FLOORS.  Every count this lint depends on has a floor, because "for each X, assert Y" is vacuously
true when X is empty -- the single largest source of false greens found in this tree.  A discovery
step that finds nothing is RED, never a pass.

Run `--selftest` first: it proves each arm above REJECTS the thing it claims to reject.  An arm that
has only ever been run against a clean tree has demonstrated nothing.
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

# Floors.  Deliberately well under today's counts (17 members, ~95 inherited declarations) so
# ordinary work never trips them, but far enough above zero that a discovery bug cannot pass.
MIN_MEMBERS = 8
MIN_INHERITED = 40

SECTIONS = ("dependencies", "dev-dependencies", "build-dependencies")


def _dep_tables(manifest: dict):
    """Yield (section_label, table) for every dependency table, including per-target ones."""
    for sect in SECTIONS:
        if manifest.get(sect):
            yield sect, manifest[sect]
    for target, tbl in (manifest.get("target") or {}).items():
        for sect in SECTIONS:
            if tbl.get(sect):
                yield f"target.{target}.{sect}", tbl[sect]


def _is_path_dep(spec) -> bool:
    return isinstance(spec, dict) and ("path" in spec or "git" in spec)


def _inherits(spec) -> bool:
    return isinstance(spec, dict) and spec.get("workspace") is True


def check(root: Path) -> list[str]:
    """Return a list of failure strings.  Empty means the tree holds."""
    failures: list[str] = []

    root_manifest = tomllib.loads((root / "Cargo.toml").read_text())
    ws = root_manifest.get("workspace") or {}
    declared_members = sorted(ws.get("members") or [])
    table = ws.get("dependencies") or {}

    if not table:
        return ["[workspace.dependencies] is missing or empty -- there is no source of truth to check."]

    inspected: list[str] = []
    used: set[str] = set()
    inherited_count = 0

    for member in declared_members:
        manifest_path = root / member / "Cargo.toml"
        if not manifest_path.is_file():
            failures.append(
                f"{member}: declared in [workspace] members but has no Cargo.toml. "
                f"A member that cannot be read is UNCHECKED, which is not the same as clean."
            )
            continue
        inspected.append(member)
        manifest = tomllib.loads(manifest_path.read_text())

        for label, deps in _dep_tables(manifest):
            for name, spec in deps.items():
                if _is_path_dep(spec):
                    continue  # workspace-internal; carries no external version
                if _inherits(spec):
                    inherited_count += 1
                    used.add(name)
                    if name not in table:
                        failures.append(
                            f"{member} [{label}]: `{name}` inherits, but there is no "
                            f"`{name}` entry in [workspace.dependencies] to inherit FROM."
                        )
                    continue
                shown = spec if isinstance(spec, str) else spec.get("version", spec)
                failures.append(
                    f"{member} [{label}]: `{name} = {shown!r}` states its own version. "
                    f"Move the version to [workspace.dependencies] and inherit with "
                    f"`{name} = {{ workspace = true }}` (features may still be added per-member)."
                )

    # (2) no orphans
    for name in sorted(set(table) - used):
        failures.append(
            f"[workspace.dependencies] `{name}` is declared but no member inherits it. "
            f"An unused pin is a version requirement nothing obeys -- delete it, or wire up the "
            f"member that was supposed to use it."
        )

    # (3) set equality, and (floors) nothing vacuous
    if sorted(inspected) != declared_members:
        missing = sorted(set(declared_members) - set(inspected))
        failures.append(
            f"inspected {len(inspected)} members but the workspace declares {len(declared_members)}; "
            f"unreadable: {missing}"
        )
    if len(inspected) < MIN_MEMBERS:
        failures.append(
            f"only {len(inspected)} member manifests were discovered (floor {MIN_MEMBERS}). "
            f"A discovery step that finds almost nothing passes almost everything -- treating that "
            f"as green is the exact false-green this floor exists to prevent."
        )
    if inherited_count < MIN_INHERITED:
        failures.append(
            f"only {inherited_count} inherited declarations were found (floor {MIN_INHERITED}). "
            f"Either the table is not actually in use or the walk is broken; both are RED."
        )

    return failures


# ── self-test ────────────────────────────────────────────────────────────────────────────────────
#
# Each case builds a tree on disk that violates exactly ONE rule and asserts the lint rejects it.
# The control case (a clean tree) must PASS, or every rejection below is meaningless -- a lint that
# fails everything is as useless as one that passes everything.

def selftest() -> int:
    import tempfile

    def build(tmp: Path, ws_deps: str, members: dict[str, str]) -> Path:
        root = tmp / "ws"
        (root).mkdir()
        member_list = "".join(f'    "{m}",\n' for m in members)
        (root / "Cargo.toml").write_text(
            f'[workspace]\nresolver = "2"\nmembers = [\n{member_list}]\n\n'
            f"[workspace.dependencies]\n{ws_deps}\n"
        )
        for name, body in members.items():
            (root / name).mkdir(parents=True)
            (root / name / "Cargo.toml").write_text(
                f'[package]\nname = "{name}"\nversion = "0.0.0"\n\n{body}\n'
            )
        return root

    # A clean tree big enough to clear both floors: 8 members, 40 inherited declarations.
    CLEAN_TABLE = "\n".join(f'dep{i} = "1"' for i in range(5))
    CLEAN_MEMBERS = {
        f"crates/m{j}": "[dependencies]\n"
        + "\n".join(f"dep{i} = {{ workspace = true }}" for i in range(5))
        for j in range(8)
    }

    cases = []

    def case(name, why, table, members, want_fail_substr):
        cases.append((name, why, table, members, want_fail_substr))

    case(
        "control: a clean tree",
        "if this fails, every rejection below proves nothing -- the lint would just reject everything",
        CLEAN_TABLE, CLEAN_MEMBERS, None,
    )
    bad = dict(CLEAN_MEMBERS)
    bad["crates/m3"] = "[dependencies]\n" + "\n".join(
        (f'dep{i} = "1"' if i == 2 else f"dep{i} = {{ workspace = true }}") for i in range(5)
    )
    case(
        "a member restates a version",
        "the exact drift the table exists to prevent: a second opinion on one dependency",
        CLEAN_TABLE, bad, "states its own version",
    )
    case(
        "an orphaned workspace entry",
        "a pin nothing obeys -- looks like governance, governs nothing",
        CLEAN_TABLE + '\nunused_dep = "9"', CLEAN_MEMBERS, "no member inherits it",
    )
    bad2 = dict(CLEAN_MEMBERS)
    bad2["crates/m1"] = "[dependencies]\n" + "\n".join(
        f"dep{i} = {{ workspace = true }}" for i in range(5)
    ) + "\nnot_in_table = { workspace = true }"
    case(
        "inheriting from a missing entry",
        "inherits from nothing; Cargo errors, but the lint must name it rather than defer",
        CLEAN_TABLE, bad2, "no `not_in_table` entry",
    )
    case(
        "too few members discovered",
        "the floor: 'for each member, assert X' is vacuously true when the walk finds two members",
        CLEAN_TABLE,
        {k: v for k, v in list(CLEAN_MEMBERS.items())[:2]},
        f"floor {MIN_MEMBERS}",
    )
    case(
        "a dev-dependency restating a version",
        "dev-dependencies are dependencies; a rule enforced on one table only is scoped to where "
        "the bug was first seen",
        CLEAN_TABLE,
        {**CLEAN_MEMBERS, "crates/m5": CLEAN_MEMBERS["crates/m5"] + '\n\n[dev-dependencies]\ndep9 = "3"'},
        "states its own version",
    )
    case(
        "a per-target dependency restating a version",
        "`[target.'cfg(...)'.dependencies]` is where the jemalloc pins live -- a walk that misses "
        "target tables would pass this tree while the real one drifts",
        CLEAN_TABLE,
        {**CLEAN_MEMBERS,
         "crates/m6": CLEAN_MEMBERS["crates/m6"] + '\n\n[target.\'cfg(unix)\'.dependencies]\ndep9 = "3"'},
        "states its own version",
    )

    bad_count = 0
    for name, why, table, members, want in cases:
        with tempfile.TemporaryDirectory() as td:
            root = build(Path(td), table, members)
            fails = check(root)
        if want is None:
            ok = not fails
            got = "passes" if ok else f"FAILS: {fails[0][:70]}"
        else:
            ok = any(want in f for f in fails)
            got = f"rejected ({len(fails)} finding(s))" if ok else "NOT REJECTED"
        if not ok:
            bad_count += 1
        print(f"  [{'ok' if ok else 'FAILED'}] {name:44} -> {got}")
        print(f"         {why}")

    if bad_count:
        print(f"\nSELF-TEST FAILED: {bad_count} of {len(cases)} arms did not behave as claimed")
        return 1
    print(f"\nself-test: {len(cases)} arms, all discriminate")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=".", help="workspace root containing the top-level Cargo.toml")
    ap.add_argument("--selftest", action="store_true", help="prove each arm rejects what it claims to")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    root = Path(args.root).resolve()
    if not (root / "Cargo.toml").is_file():
        print(f"FAIL: no Cargo.toml at {root} -- cannot check what cannot be read.", file=sys.stderr)
        return 1

    failures = check(root)
    if failures:
        print(f"FAIL: {len(failures)} dependency-declaration problem(s)\n", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        print(
            "\nOne version requirement per dependency, written once in [workspace.dependencies].",
            file=sys.stderr,
        )
        return 1

    ws = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]
    print(
        f"workspace dependencies OK: {len(ws.get('dependencies') or {})} pins, "
        f"{len(ws.get('members') or [])} members, every external dependency inherits, no orphans."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
