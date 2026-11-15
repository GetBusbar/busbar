---
title: "BUSBAR-9024: More expired writers remain than one start closes (the next start continues)"
description: "What Busbar error BUSBAR-9024 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9024
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The start-up pass closes at most 256 expired writers per start, so its cost stays bounded. More remained; the next start of any gateway on this store continues with them.

## How to fix it

None if starts continue. Many expired writers point at many processes that did not retire: check why shutdowns are not completing.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
