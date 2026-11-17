---
title: "BUSBAR-8014: auth.chain is empty — OPEN RELAY (every request admitted unauthenticated)"
description: "What Busbar error BUSBAR-8014 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8014
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The auth chain is written empty (`auth: { chain: [] }`, the operator's explicit open-relay acknowledgement), so every data-plane request is admitted unauthenticated — an OPEN RELAY forwarding anyone's traffic on your upstream credentials. Emitted at ERROR (not warn, which RUST_LOG=error would suppress) and unconditionally on stderr so the state cannot be masked by log configuration. A configuration with no `auth:` block is refused with this code instead of booting: busbar never runs an open relay by omission, and the 1.5.5 upgrade writes `auth: { chain: [] }` for a 1.5.5 config that had none. Acceptable only for local development.

## How to fix it

Configure `auth.chain` (`chain: [keys]` with virtual keys minted through the admin API, and/or an auth plugin) before exposing busbar to any untrusted network. To run unauthenticated deliberately, write `auth: { chain: [] }`. This is the same open-relay condition as BUSBAR-4004, surfaced at boot.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
