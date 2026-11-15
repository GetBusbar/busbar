---
title: "BUSBAR-9013: Waiting on another writer's first start of this dataset (no listener bound yet)"
description: "What Busbar error BUSBAR-9013 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9013
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

Another process owns this dataset's first start and has not published it, and its progress rows (birth record, writer row, R0 progress row) changed within the stall window, so this process waits instead of retiring it. It binds no listener while it waits. The line names the owner's writer id, how long ago its progress last changed and when this process takes over if nothing changes. A restart resets the wait.

## How to fix it

Let it wait: it is admitted once the owner publishes, or takes over once the owner stops making progress for the window. Do not stop or restart it before the named takeover time; give the supervisor a startup budget of at least 200 + 105 x P seconds (P = conditional-records planes), see docs/operations.md First start with several replicas.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
