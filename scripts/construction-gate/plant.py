#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# plant.py -- the self-test's saboteur for THE CONSTRUCTION GATE.
#
# Given a scratch copy of the tree, it first restores every file it ever touches from the pristine
# copy, then plants exactly ONE construction violation for the named rule. The self-test in
# scripts/construction-gate.sh runs the gate on the result and requires exactly one FAIL row naming
# that rule. A rule whose planted violation goes unnoticed is a rule that is not measuring anything.
#
#   plant.py <rule-id> <pristine-root> <scratch-root> <calibrated.toml> [baseline-rows.json]
#
# Exit 3 = "nothing to plant": the rule's subject is absent from this tree (a twin already retired,
# a file not yet written); the self-test notes it and moves on rather than failing.

import json
import os
import shutil
import sys
import tomllib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rules  # noqa: E402

# Every file any plant edits; all are restored before each plant so plants never stack. A file
# that the pristine copy does not have (deleted upstream, or created by a plant) is REMOVED from
# the scratch copy on restore, so a plant can create a file and the next plant starts clean.
TOUCHED = [
    "crates/busbar-llm/src/engine/walk.rs",
    "crates/busbar-llm/src/engine/select.rs",
    "crates/busbar-llm/src/arrival.rs",
    "crates/busbar-llm/src/native_ingress.rs",
    "crates/busbar-llm/src/unit/route.rs",
    "crates/busbar-voice/src/lib.rs",
    "crates/busbar-substrate/src/lib.rs",
    "crates/busbar-substrate/src/plane_host/mod.rs",
    "crates/busbar-substrate/src/teller/run.rs",
    "crates/busbar-core/src/router.rs",
]


def restore(pristine, scratch):
    for rel in TOUCHED:
        src, dst = os.path.join(pristine, rel), os.path.join(scratch, rel)
        if os.path.exists(src):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(src, dst)
        elif os.path.exists(dst):
            os.remove(dst)
            # a directory a plant created for the file goes with it, once empty
            d = os.path.dirname(dst)
            if os.path.isdir(d) and not os.listdir(d):
                os.rmdir(d)


def append(scratch, rel, text):
    path = os.path.join(scratch, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n" + text + "\n")


def nothing_to_plant(reason):
    print(f"plant: nothing to plant: {reason}")
    sys.exit(3)


def plant(rule, pristine, scratch, cfg, baseline):
    if rule == "one-attempt-seam":
        # The planted send lives in a file that is NOT the attempt file, whatever the tree calls
        # the attempt file today.
        append(scratch, "crates/busbar-llm/src/engine/select.rs",
               "pub(crate) async fn planted_second_attempt(rt: &Arc<NativeRuntime>, hreq: Req) {\n"
               "    let _ = EngineTables::new(rt).client().get().request(hreq);\n}")
    elif rule == "request-path-fn-size":
        n = cfg["rules"]["request-path-fn-size"]["max_lines"] + 10
        body = "\n".join("    let _planted = 1;" for _ in range(n))
        append(scratch, "crates/busbar-llm/src/arrival.rs", f"fn planted_giant() {{\n{body}\n}}")
    elif rule == "ports-only:busbar-voice":
        append(scratch, "crates/busbar-voice/src/lib.rs",
               "fn planted_reach() { let _ = busbar_core::planted::Thing; }")
    elif rule == "ports-only-tests:busbar-voice":
        append(scratch, "crates/busbar-voice/src/lib.rs",
               "#[cfg(test)]\nmod planted_tests {\n"
               "    fn t() { let _ = busbar_core::planted::Thing; }\n}")
    elif rule == "no-uninstalled-seam":
        append(scratch, "crates/busbar-substrate/src/lib.rs",
               "static PLANTED_SEAM: std::sync::OnceLock<u8> = std::sync::OnceLock::new();\n"
               "pub fn install_planted_seam(v: u8) { let _ = PLANTED_SEAM.set(v); }")
    elif rule == "neutral-no-dialect":
        append(scratch, "crates/busbar-substrate/src/lib.rs",
               'pub fn planted_dialect() -> &\'static str { "openai" }')
    elif rule == "single-terminal":
        append(scratch, "crates/busbar-core/src/router.rs",
               "fn planted_terminal() { crate::ingress::finish_inner(); }")
    elif rule == "token-sealed":
        # A hold opened outside the Teller: a forged token.
        append(scratch, "crates/busbar-substrate/src/plane_host/mod.rs",
               "fn planted_forge() { let _ = crate::teller::Hold::open(None, None, false); }")
    elif rule == "teller-step-order":
        rel = cfg["rules"]["teller-step-order"]["file"]
        path = os.path.join(scratch, rel)
        if not os.path.exists(path):
            nothing_to_plant(f"{rel} does not exist yet")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        # Swap the first two steps: the loop now decodes before it has an arrival.
        src = src.replace(".arrival(", ".__swap__(").replace(".decode(", ".arrival(").replace(".__swap__(", ".decode(")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(src)
    elif rule == "one-teller-loop":
        # Two entries into the loop from one plane crate.
        append(scratch, "crates/busbar-llm/src/native_ingress.rs",
               "async fn planted_loop_a() { let _ = busbar_substrate::teller::run_unit(a, b).await; }\n"
               "async fn planted_loop_b() { let _ = busbar_substrate::teller::run_unit(a, b).await; }")
    elif rule == "one-teller-loop:run_gauntlet":
        append(scratch, "crates/busbar-llm/src/native_ingress.rs",
               "async fn planted_legacy() { let _ = busbar_substrate::plane_host::run_gauntlet(a, b).await; }")
    elif rule == "no-response-escapes-audit":
        # A step file (not audit.rs) that hands a Response back.
        append(scratch, "crates/busbar-llm/src/unit/route.rs",
               "pub(crate) fn planted_escape() -> axum::response::Response { todo!() }")
    elif rule == "terminal-doors-in-audit-step":
        append(scratch, "crates/busbar-llm/src/native_ingress.rs",
               "fn planted_door(host: &dyn Host) { host.finish_rejected(a, b, c, d); }")
    elif rule == "one-pick-site":
        append(scratch, "crates/busbar-llm/src/engine/select.rs",
               "async fn planted_pick() { let _ = pick_among(a, b, c, d, e, f, g).await; }")
    elif rule == "duplicate-dispatch":
        # Copy a brace-balanced block of the hot-path twin into the degraded twin, from a region
        # the baseline did not already report as shared, so the duplicated-line total must rise.
        tree = rules.Tree(scratch, cfg)
        names = cfg["rules"]["duplicate-dispatch"]["twins"]
        found = [tree.find_fn_by_name(n) for n in names]
        if not all(found):
            nothing_to_plant("twin(s) absent: " + ", ".join(n for n, f in zip(names, found) if not f))
        a = found[0][0]
        b = found[1][0]
        taken = []
        for r in baseline or []:
            if r["id"] == "duplicate-dispatch":
                taken = r.get("blocks", [])
        want = cfg["rules"]["duplicate-dispatch"]["min_block_lines"] + 20
        lines_a = tree.files[a.path]
        start = None
        for s in range(a.body_start, a.end - want):
            window = lines_a[s:s + want]
            if any(not (s + want < lo or s > hi) for lo, hi in taken):
                continue
            if sum(l.blank.count("{") for l in window) == sum(l.blank.count("}") for l in window):
                start = s
                break
        if start is None:
            sys.exit("plant: no brace-balanced window free of baseline blocks in the hot-path twin")
        with open(os.path.join(pristine, a.path), encoding="utf-8") as fh:
            src = fh.read().split("\n")
        block = src[start:start + want]
        bpath = os.path.join(scratch, b.path)
        with open(bpath, encoding="utf-8") as fh:
            dst = fh.read().split("\n")
        dst[b.body_start:b.body_start] = block
        with open(bpath, "w", encoding="utf-8") as fh:
            fh.write("\n".join(dst))
    else:
        sys.exit(f"plant: no plant defined for rule {rule}")


def main():
    rule, pristine, scratch, toml = sys.argv[1:5]
    baseline = None
    if len(sys.argv) > 5 and os.path.exists(sys.argv[5]):
        with open(sys.argv[5], encoding="utf-8") as fh:
            baseline = json.load(fh)
    with open(toml, "rb") as fh:
        cfg = tomllib.load(fh)
    restore(pristine, scratch)
    if rule != "none":
        plant(rule, pristine, scratch, cfg, baseline)


if __name__ == "__main__":
    main()
