---
title: "BUSBAR-3410: A registration's allow_private was replaced by exact advanced.allow_destinations entries"
description: "What Busbar error BUSBAR-3410 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3410
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

An MCP server (`tools.<server>`) or A2A agent (`agents.<agent>`) set the retired `allow_private`. The migration removed the key and listed exactly the hosts that registration dials in `advanced.allow_destinations` (never a wildcard or a network, never a cloud-metadata host). A plaintext `http://` registration to a non-loopback host is refused at 1.6.0: the planes admit `http://` to loopback only.

## How to fix it

Review the listed hosts. Move a non-loopback `http://` registration to `https://`; busbar has no per-destination plaintext switch.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
