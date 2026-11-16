---
title: "BUSBAR-3135: A registration still carries the retired per-registration private-address switch"
description: "What Busbar error BUSBAR-3135 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3135
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## What it means

A plane registration (an MCP server under `tools:`, an A2A agent under `agents:`) sets `allow_private`. 1.6.0 has one private-address policy for every outbound connection, `advanced.block_private_addresses` with `advanced.allow_destinations`; a per-registration switch that lifted it for one plugin is retired. The configuration is refused, naming the registration, rather than read with the switch ignored or applied.

## How to fix it

Delete `allow_private` and add the host (or its address) to `advanced.allow_destinations`. A cloud-metadata address stays refused whatever is listed.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
