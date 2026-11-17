---
title: "BUSBAR-2050: Audit lines have gone unstamped for too long"
description: "What Busbar error BUSBAR-2050 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-2050
---

**Area:** Audit chain (2xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The oldest audit line no stamp covers yet is older than the alert threshold (ten times audit.seal_every, at least one second). The notary is backing off a failing signer or store, or it has stopped. Lines are durable and linked; a crash now leaves a longer unstamped tail for the next process on this host to seal or report.

## How to fix it

Look for BUSBAR-2049 just before this line and act on its reason. The gauge audit_unstamped_age_ms shows the current age.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
