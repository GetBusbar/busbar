---
title: "BUSBAR-9018: First start not handed over on exit (the next start waits)"
description: "What Busbar error BUSBAR-9018 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9018
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

This process owned an unpublished first start and exited, but retiring its writer row did not complete within the exit budget (5 s), was refused, or its outcome is unknown. The next start of this dataset waits up to the named window before it takes over, as after a crash.

## How to fix it

Check the store's health. Keep the next start running for at least the named window so it can take over; restarting it early resets the wait.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
