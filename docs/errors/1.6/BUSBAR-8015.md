---
title: "BUSBAR-8015: Store settings hold a secret reference that does not resolve here"
description: "What Busbar error BUSBAR-8015 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8015
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A governance-store `settings` value holds a secret reference that does not resolve on this boot. busbar warns rather than fails, because the store is restart-to-apply and staging a ref whose secret the orchestrator mounts on the next deploy is a legitimate workflow. But if the secret is still absent at the next restart, THAT restart will fail in resolve_settings before serving.

## How to fix it

Ensure the named store secret reference resolves before the next restart. If you are staging it for an upcoming deploy, no action now; otherwise fix the reference so the next restart does not die resolving it.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
