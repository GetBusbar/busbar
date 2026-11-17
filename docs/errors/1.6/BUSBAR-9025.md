---
title: "BUSBAR-9025: Waiting on another owner's record-format conversion of this dataset (no listener bound yet)"
description: "What Busbar error BUSBAR-9025 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9025
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

This dataset's records are being converted to a newer format by another process (the migration owner the manifest names), and the conversion's rows (dataset root, manifest, step cursor, owner's writer row) changed within the stall window, so this process waits instead of claiming it. It binds no listener while it waits. The line names the owner's writer id, how long ago the conversion last changed and when this process claims it if nothing changes. A restart resets the wait.

## How to fix it

Let it wait: once the owner publishes the new format this process is admitted, and once the owner stops making progress for the window this process claims the conversion and resumes it from the step cursor. A record-format upgrade needs the whole fleet stopped (docs/migration-1.6.md, Shared datasets with a changing core record format): stop any process of the old release that still reaches this store.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
