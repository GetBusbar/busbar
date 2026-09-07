#!/usr/bin/env python3
"""Plant a break in one production cell, run that crate's tests, revert, report."""
import subprocess
import sys

W = "/Users/matthew/Developer/GetBusbar/busbar/.claude/worktrees/agent-a0431314c172646d5"

# (label, crate, relative file, old snippet, new snippet)
PLANTS = [
    ("journal resume stops flooring its number to the log",
     "busbar-unit-wal", "crates/busbar-unit-wal/src/journal.rs",
     "self.next_seq = u64::max(self.next_seq, self.log.next_free_seq(self.node));",
     "self.next_seq = self.next_seq;"),

    ("the chain stops checking that a number follows its predecessor",
     "busbar-unit-wal", "crates/busbar-unit-wal/src/journal.rs",
     "        if let Some(expected) = expected_seq {\n            if record.node_seq != expected {",
     "        if let Some(expected) = expected_seq {\n            if false && record.node_seq != expected {"),

    ("make_room stops counting the break record it is about to seal",
     "busbar-unit-wal", "crates/busbar-unit-wal/src/journal.rs",
     "let wanted = held.saturating_add(incoming).saturating_add(1);",
     "let wanted = held.saturating_add(incoming);"),

    ("the idempotence check forgets the holes below a node's mark",
     "busbar-unit-wal", "crates/busbar-unit-wal/src/wal.rs",
     "Some(&mark) => node_seq <= mark && !self.gaps.contains(&(node, node_seq)),",
     "Some(&mark) => node_seq <= mark,"),

    ("a restart resumes from segment zero instead of the log's end",
     "busbar-unit-wal", "crates/busbar-unit-wal/src/wal.rs",
     "let mut index = factory.highest_index()?.unwrap_or(0);",
     "let mut index = 0u64;"),

    ("a settlement lets an unused reservation go negative",
     "busbar-unit-ledger", "crates/busbar-unit-ledger/src/settle.rs",
     "let released = (reserved - settled).max(0);",
     "let released = reserved - settled;"),

    ("the identity adds the carried overdraft instead of subtracting it",
     "busbar-unit-ledger", "crates/busbar-unit-ledger/src/identity.rs",
     "        - (now.overdraft_carried() - since.overdraft_carried())",
     "        + (now.overdraft_carried() - since.overdraft_carried())"),

    ("the metering key drops the length frame from its lane",
     "busbar-unit-ledger", "crates/busbar-unit-ledger/src/migration.rs",
     'BucketScope::Pool(format!("meter:{}:{lane}:{}", lane.len(), self.provider))',
     'BucketScope::Pool(format!("meter:{lane}:{}", self.provider))'),

    ("a closed window is checked with the residual instead of both sides",
     "busbar-unit-ledger", "crates/busbar-unit-ledger/src/identity.rs",
     "    if moved.accounted != 0 {\n        Err(moved.accounted)",
     "    if moved.amount() != 0 {\n        Err(moved.accounted)"),

    ("the two GET-bound verbs go back to spending a mutation slot",
     "busbar-unit-verbs", "crates/busbar-unit-verbs/src/rate.rs",
     "|| crate::verb::READ_ONLY_NEW_VERBS.contains(&verb)\n",
     ""),

    ("the generic path stops refusing the two minting verbs",
     "busbar-unit-verbs", "crates/busbar-unit-verbs/src/verbs.rs",
     "if verb == KernelVerb::PostKeys || verb == KernelVerb::PostKeysIdRotate {",
     "if false {"),

    ("dual control admits a mutation nobody has approved",
     "busbar-unit-verbs", "crates/busbar-unit-verbs/src/posture.rs",
     "        ApprovalState::NotYetApproved => Err(Refusal::new(\n            RefusalStep::Admit,\n            ReasonCode::ApprovalPending,\n        )),",
     "        ApprovalState::NotYetApproved => Ok(()),"),

    ("the rotate slot goes back to joining its id on a separator",
     "busbar-unit-verbs", "crates/busbar-unit-verbs/src/verbs.rs",
     'format!("rotate:{}:{id}:{k}", id.len())',
     'format!("rotate:{id}:{k}")'),

    ("the sweep goes back to forgetting an in-flight reservation",
     "busbar-unit-verbs", "crates/busbar-unit-verbs/src/idempotency.rs",
     "v.is_none() || now.saturating_sub(*t) < IDEMPOTENCY_TTL_SECS",
     "now.saturating_sub(*t) < IDEMPOTENCY_TTL_SECS"),

    ("a replay that had to roll stops reporting that it replayed",
     "busbar-unit-wal", "crates/busbar-unit-wal/src/wal.rs",
     "ack.replayed_lost_batch |= replaying;",
     "ack.replayed_lost_batch |= false;"),
]


def run(label, crate, rel, old, new):
    path = f"{W}/{rel}"
    original = open(path).read()
    if old not in original:
        return label, "PATTERN-NOT-FOUND", ""
    open(path, "w").write(original.replace(old, new, 1))
    try:
        out = subprocess.run(
            ["cargo", "test", "-p", crate],
            cwd=W, capture_output=True, text=True, timeout=900,
        )
        blob = out.stdout + out.stderr
        failed = [l for l in blob.splitlines()
                  if l.startswith("test ") and "FAILED" in l]
        errs = [l for l in blob.splitlines() if l.startswith("error")]
        if failed:
            return label, "CAUGHT", failed[0].strip()
        if errs:
            return label, "CAUGHT (does not compile)", errs[0].strip()
        return label, "SURVIVED", ""
    finally:
        open(path, "w").write(original)


if __name__ == "__main__":
    for p in PLANTS:
        label, verdict, detail = run(*p)
        print(f"{verdict:26} | {label}")
        if detail:
            print(f"{'':26} |   {detail}")
        sys.stdout.flush()
