---
title: "BUSBAR-8020: Provider api_key did not resolve (boot refuses)"
description: "What Busbar error BUSBAR-8020 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8020
---

**Area:** Governance & cost (8xxx) · **Severity:** fatal · **Since:** 1.6.0

## What it means

A provider's `api_key` secret reference could not be resolved — an unset environment variable, a missing file, a value or file that is empty or whitespace-only, an unknown module, or a secret plugin that failed — so busbar refuses to start. It does not fall back to an empty credential: that lane could never authenticate, would report healthy, would be skipped by the health prober (no key, no probe), and would answer every request routed to it with a 401 from the upstream. The diagnostic names the provider and the secret module (`secret module '<module>'`), never the value.

## How to fix it

Fix the reference so it resolves (set the variable, mount the file, install and trust the secret plugin), or — if this upstream genuinely takes NO credential, such as a local model server — declare that explicitly with `api_key: none`, which starts the lane with no credential and sends no auth header. `--validate` reports the same refusal before you deploy.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
