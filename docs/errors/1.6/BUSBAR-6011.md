---
title: "BUSBAR-6011: First-party anti-downgrade floor unreadable (booting with NO first-party floor)"
description: "What Busbar error BUSBAR-6011 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-6011
---

**Area:** Plugins (6xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The persisted per-plugin-name high-water marks — the automatic first-party anti-downgrade floor — could not be read or were not valid, so busbar booted with NO first-party floor. Security-relevant: while the floor is absent, a validly-signed but OLD first-party artifact planted in the plugins directory would load without being refused as a downgrade. The floor re-establishes itself as plugins load successfully. busbar fails SOFT here on purpose: refusing the boot would let anyone able to corrupt one file take the node down.

## How to fix it

Check the data directory is readable and that `plugin-highwater.json` beneath it is intact (the log names the path and the exact problem). Deleting the file is safe — the floor rebuilds from the next successful load — but it does re-open the replay window until it does.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
