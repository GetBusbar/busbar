---
title: "BUSBAR-9017: First start handed over on exit (writer retired)"
description: "What Busbar error BUSBAR-9017 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9017
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

This process owned an unpublished first start and exited before publishing it (a boot refusal, a signal, or a one-shot command), so it retired its own writer row on the way out. The birth record is unchanged; the next start of this dataset, here or on another replica, takes over at once with no wait.

## How to fix it

None for the hand-over. Fix the reason the process exited, which is printed just before this line.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
