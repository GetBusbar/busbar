---
title: "BUSBAR-3134: An allowlist entry names a cloud-metadata destination"
description: "What Busbar error BUSBAR-3134 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3134
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## What it means

An `advanced.allow_destinations` entry is a cloud-metadata host name (such as `metadata.google.internal`), a metadata address (such as `169.254.169.254`, `fd00:ec2::254` or an IPv6 link-local address), or a /32 or /128 network equal to one. Cloud metadata is refused for every outbound connection, in every egress class, and no configuration admits it, so the entry is refused at startup rather than silently ignored. A wider network that merely covers a metadata address (such as `169.254.0.0/16`) loads, and still never admits the metadata address.

## How to fix it

Remove the entry named in the message. A workload that needs cloud credentials uses workload-identity federation (IRSA, AKS workload identity, GKE workload identity federation) through a projected token file, never the instance metadata endpoint.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
