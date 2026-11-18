---
title: "BUSBAR-8019: Metering accumulator at cap: a cell was coalesced into an overflow sentinel"
description: "What Busbar error BUSBAR-8019 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8019
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The write-behind metering accumulator (pending_metering) reached its cap while a NEW (key_id, bucket, model, provider) cell arrived — a sustained governance-store outage with diverse keys/models, where every flush re-queues the failed cells while new ones keep arriving. Rather than grow without bound OR silently drop billable usage, busbar COALESCES the arriving cell's counts into a per-bucket overflow sentinel: the day's token and request TOTALS are preserved, only their per-key/model/provider ATTRIBUTION is collapsed. Each coalesce also increments busbar_metering_pending_coalesced_total. The metering flush pass emits the warning, at most once per minute, naming how many cells were coalesced since the previous line and the bucket of the latest; the counter carries the running total. If the metering flush is not running, no line is logged and only the counter moves.

## How to fix it

Restore the governance store — the accumulator overflows only under a sustained write outage. Usage is not lost (totals are retained under the overflow sentinel key), but once the store recovers the retained deltas flush and normal per-key attribution resumes. A steadily climbing coalesced counter means the outage has outlasted the cap.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
