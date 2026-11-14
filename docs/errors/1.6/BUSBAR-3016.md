---
title: "BUSBAR-3016: --list-plugins fell back to the default plugins block (config unreadable)"
description: "What Busbar error BUSBAR-3016 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3016
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

`busbar --list-plugins` could not read/parse config.yaml, so it inventoried the plugins directory using the DEFAULT `plugins:` block (default dir and trust policy) rather than the deployment's configured one. The inventory shown may not reflect the directory, trust policy, or store selection the running gateway would actually use.

## How to fix it

This is informational and best-effort pre-deployment. To inventory against the real config, fix config.yaml so it parses (run `busbar --validate` to see the error) and re-run `--list-plugins`.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
