---
title: "BUSBAR-8101: The admin resource named in the request does not exist"
description: "What Busbar error BUSBAR-8101 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8101
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The path names a resource (a key, a group, a hook, an exporter, a plugin) that this deployment does not have, or one that cannot exist in its current mode (a key read with governance disabled). The response's `message` names the missing thing.

## How to fix it

List the collection (for example `GET /api/v1/admin/keys`) to find the right name or id, or create the resource first.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
