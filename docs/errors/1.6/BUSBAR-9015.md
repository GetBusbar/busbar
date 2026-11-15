---
title: "BUSBAR-9015: First-start takeover not confirmed (outcome unknown or refused)"
description: "What Busbar error BUSBAR-9015 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9015
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

This process tried to take over a stalled first start, but the store did not confirm it: either the outcome is unknown (the previous writer may or may not have been retired) or the store refused it with no effect. Nothing claims the takeover happened; boot then refuses with the store admission error that follows this line.

## How to fix it

Check the store's health and restart. The next start reads the dataset as it is: it waits on the owner, or takes over at once if the earlier takeover did apply.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
