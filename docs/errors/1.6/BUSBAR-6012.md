---
title: "BUSBAR-6012: First-party anti-downgrade floor could not be persisted (it will not survive a restart)"
description: "What Busbar error BUSBAR-6012 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-6012
---

**Area:** Plugins (6xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

busbar raised the per-plugin-name high-water marks — the automatic first-party anti-downgrade floor — but could not write them to the data directory. The floor still applies to THIS process; it will not survive a restart, so the replay window reopens at the next boot until a load re-establishes it.

## How to fix it

Make the configured data directory writable (the log names the underlying I/O error). A node that cannot write its data directory usually has a larger problem than this notice.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
