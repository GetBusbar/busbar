# Busbar diagnostics catalog

Every operator-facing log line from busbar carries a stable `BUSBAR-NNNN` code in its `diag` field. Find the code below for what it means, whether it needs action, and what to do. This page is generated from the code — do not edit by hand.

Codes are grouped by class (the thousands digit).

## 1xxx — Durability & write-through

<a id="durable-writethrough-below-floor"></a>
### BUSBAR-1001 — Durable audit write-through skipped (seq at or below the recovered floor)

- **Severity:** benign_recurring
- **Since:** 1.6.0
- **Slug:** `durable-writethrough-below-floor`

An audit entry's sequence number is at or below the recovered durable floor, so it is already persisted under that seq and the write-through is correctly skipped — the entry is retained in the in-memory ring. A single occurrence at boot is expected after a durable-store restore.

**What to do:** None — self-healing. If it warns repeatedly for DIFFERENT sequence numbers, suspect a second node writing the same durable store (see BUSBAR-1002).

<a id="durable-second-writer-detach"></a>
### BUSBAR-1002 — Durable audit log has another writer — this node detached its durable sink

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `durable-second-writer-detach`

The durable audit store's tail is ahead of what this node last persisted, which can only mean a second busbar is writing the same store. The durable audit log supports exactly ONE writer; two nodes overwrite each other's entries and break the hash chain, which the next boot reports as tampering. This node has detached its durable sink and now audits only to its ephemeral in-memory ring.

**What to do:** Ensure exactly one busbar instance is pointed at this durable audit store. Give the other instance its own store, then restart this node to re-attach a durable sink.

<a id="durable-audit-ring-unreconciled"></a>
### BUSBAR-1003 — Durable audit write-through held — ring not yet reconciled with the durable tail

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `durable-audit-ring-unreconciled`

This process's in-memory audit ring is not yet reconciled with the durable tail (the boot restore did not read or verify it, and a retry read is still failing), so the write-through is held rather than risk overwriting durable history. The entry is retained in the RAM ring and will backfill once the store answers with a verifiable tail.

**What to do:** Check the durable audit store is reachable and returns a verifiable tail. This clears itself once a tail read succeeds (logged as recovery at info level).

<a id="durable-audit-writethrough-failed"></a>
### BUSBAR-1004 — Durable audit write-through failed (entry retained in the in-memory ring)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `durable-audit-writethrough-failed`

Appending an audit entry to the durable store failed — typically a durable-store outage. The entry is retained in the in-memory ring and the state snapshot and will backfill on the next successful write-through, so nothing is lost from the ring.

**What to do:** Investigate the durable audit store outage. No entries are lost from the in-memory ring; they persist once the store recovers and the next mutation backfills them.

<a id="durable-audit-backfill-gap"></a>
### BUSBAR-1005 — Durable audit chain has an unrepairable gap (a seq was pruned before it persisted)

- **Severity:** actionable
- **Since:** 1.6.0
- **Slug:** `durable-audit-backfill-gap`

A durable-chain sequence number is no longer in the in-memory ring (it was pruned during a store outage longer than the ring bound), so it can never be backfilled in-process. The durable chain therefore has an unrepairable gap at that seq and catch-up stops below the hole. This is real durable-audit data loss for that seq.

**What to do:** Recent entries remain in the in-memory ring, but the DURABLE log has a permanent gap at the named seq. Resolve the store outage that caused it; restore the durable store from a backup if the durable chain's completeness is required for compliance.

