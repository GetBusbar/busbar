---
title: "BUSBAR-3136: A retired cloud-metadata carve-out key is set"
description: "What Busbar error BUSBAR-3136 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3136
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## What it means

The configuration sets `security.allow_metadata_hosts`, `security.allow_all_metadata: true` or a provider's `allow_metadata_hosts`. In 1.6.0 cloud metadata is refused for every outbound connection, in every egress class, and no configuration admits it, so these 1.5.5 carve-outs are retired. The configuration is refused rather than read with the carve-out ignored. `security.blocked_metadata_hosts` still extends the denylist.

## How to fix it

Remove the keys. A workload that needs cloud credentials uses workload-identity federation (IRSA, AKS workload identity, GKE workload identity federation) through a projected token file, never the instance metadata endpoint.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
