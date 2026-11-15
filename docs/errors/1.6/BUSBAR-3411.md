---
title: "BUSBAR-3411: A retired cloud-metadata carve-out key was removed"
description: "What Busbar error BUSBAR-3411 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3411
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The migration removed `security.allow_metadata_hosts`, `security.allow_all_metadata` or a provider's `allow_metadata_hosts`, naming each removed entry. 1.6.0 refuses cloud metadata for every outbound connection and no configuration admits it; a destination the carve-out reached is now refused.

## How to fix it

If a removed entry reached an instance credential endpoint, move that workload to workload-identity federation (IRSA, AKS workload identity, GKE workload identity federation) through a projected token file.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
