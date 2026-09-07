#!/usr/bin/env python3
"""Red-before-green driver for M8.

Each entry is one mutation of the shipped implementation and the test that must
go red under it. The file is restored between mutations, so a mutation that
failed to apply is reported rather than silently skipped.
"""
import subprocess
import sys

SRC = "crates/busbar/src/root/ledger_identity.rs"

MUTATIONS = [
    (
        "the walk reads the cache instead of the lookup",
        "the_walk_answers_from_the_quantities_and_never_from_the_cache",
        "            Ok(priced) => {\n                if priced.lane_unpriced {",
        "            Ok(mut priced) => {\n                priced.priced_nanos = u128::try_from(line.cached.priced_nanos).unwrap_or(0);\n                if priced.lane_unpriced {",
    ),
    (
        "the walk prices every line at the head's instant rather than its own",
        "a_mid_window_entry_is_exactly_what_makes_the_legacy_derivation_diverge",
        "        match price_line(line, view, line.tier_bp) {",
        "        let mut line_at_head = line.clone();\n        line_at_head.arrived_ms = u64::MAX;\n        let line = &line_at_head;\n        match price_line(line, view, line.tier_bp) {",
    ),
    (
        "a lane the card is silent about is absorbed rather than reported",
        "a_lane_the_card_is_silent_about_is_reported_beside_its_row",
        "                if priced.lane_unpriced {\n                    unpriceable.push(Unpriced {",
        "                if false {\n                    unpriceable.push(Unpriced {",
    ),
    (
        "an instant no entry covers is folded in as a zero",
        "an_instant_no_entry_covers_lands_on_no_row_and_is_listed",
        "            Err(why) => unpriceable.push(Unpriced {\n                node: line.node,\n                node_seq: line.node_seq,\n                why: busbar_unit_ledger::recompute::divergence_of(why),\n            }),",
        "            Err(_) => {\n                snapshot.entry(row_of(line)).or_default();\n            }",
    ),
    (
        "two currencies sum into one reconciliation",
        "two_currencies_never_sum_into_one_reconciliation",
        "        if line.currency != currency {\n            continue;\n        }",
        "",
    ),
    (
        "the statement residual answers zero whatever the two sides hold",
        "a_line_folded_onto_the_wrong_row_moves_one_sum_and_not_the_other",
        "    statement.total_nanos().saturating_sub(identity)",
        "    let _ = identity;\n    0",
    ),
    (
        "a stale cache after an amendment is counted as an alarm",
        "a_cache_behind_a_moved_head_is_stale_rather_than_alarming",
        "            .filter(|f| f.verdict == Verdict::Alarm)\n            .count()",
        "            .filter(|f| f.verdict == Verdict::Alarm || f.verdict == Verdict::Stale)\n            .count()",
    ),
    (
        "a hand edit under an unmoved head is laundered into the quiet path",
        "a_cache_edited_under_an_unmoved_head_alarms_and_is_corrected",
        "    pub fn alarms(&self) -> bool {\n        self.alarming() > 0\n    }",
        "    pub fn alarms(&self) -> bool {\n        false\n    }",
    ),
    (
        "the pass forgets which trigger it ran under",
        "the_trigger_is_recorded_and_is_never_an_input_to_the_arithmetic",
        "    reconciliation_pass(PassTrigger::Boot, watermark, lines, archive)",
        "    reconciliation_pass(PassTrigger::OnDemand, watermark, lines, archive)",
    ),
    (
        "the boot pass starts over instead of resuming from its watermark",
        "a_pass_resumes_from_the_watermark_it_was_handed",
        "pub fn boot_pass(\n    watermark: Watermark,",
        "pub fn boot_pass(\n    _watermark: Watermark,",
    ),
    (
        "a checkpoint verifies at any snapshot that is asked about",
        "a_checkpoint_verifies_at_the_snapshot_it_was_sealed_as_of_and_at_no_other",
        "        Some(sealed) if sealed != at => Err(CheckpointRefusal::NotAsOf { sealed, asked: at }),",
        "",
    ),
    (
        "the digest is not taken once the snapshot matches",
        "an_edited_checkpoint_body_is_refused_at_its_own_snapshot",
        "        Some(_) if !checkpoint.body_hash_verifies() => Err(CheckpointRefusal::BodyEdited),",
        "",
    ),
    (
        "a checkpoint that names no history answers as if it named this one",
        "a_checkpoint_that_predates_the_history_is_refused_at_every_snapshot",
        "        None => Err(CheckpointRefusal::PredatesHistory { asked: at }),",
        "        None => Ok(()),",
    ),
]


def run(test):
    out = subprocess.run(
        ["cargo", "test", "-p", "busbar", "--bin", "busbar", test],
        capture_output=True,
        text=True,
    )
    return out.returncode, out.stdout + out.stderr


def main():
    original = open(SRC).read()
    failures = []
    try:
        for name, test, find, replace in MUTATIONS:
            if original.count(find) != 1:
                print(f"SKIP  {name}: anchor matched {original.count(find)} times")
                failures.append(name)
                continue
            open(SRC, "w").write(original.replace(find, replace, 1))
            code, out = run(test)
            open(SRC, "w").write(original)
            if code == 0:
                print(f"NOT RED  {name} -> {test}")
                failures.append(name)
            else:
                line = next(
                    (l for l in out.splitlines() if "panicked at" in l or "assertion" in l),
                    "",
                )
                print(f"RED  {name}\n     {test}\n     {line.strip()[:160]}")
    finally:
        open(SRC, "w").write(original)

    code, out = run("root::ledger_identity")
    print(f"\nrestored: {'GREEN' if code == 0 else 'RED'}")
    if failures:
        print("\nnot proved red:", failures)
        sys.exit(1)


if __name__ == "__main__":
    main()
