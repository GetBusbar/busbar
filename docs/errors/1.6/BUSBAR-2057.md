---
title: "BUSBAR-2057: Sealing a crashed predecessor is failing and is retried"
description: "What Busbar error BUSBAR-2057 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-2057
---

**Area:** Audit chain (2xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A step of sealing a crashed predecessor's audit tail (fence, tail read, sign or seal write) failed or did not answer within one second. The step is retried on a capped backoff of up to one second, and a write is never dropped mid-flight. An Info line follows once the node is sealed.

## How to fix it

Check the store's health and the audit signing key. If the process stops first, the next process on the host seals the node.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
