---
title: "BUSBAR-3016: --list-plugins refused a config that exists but is not readable"
description: "What Busbar error BUSBAR-3016 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3016
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

`busbar --list-plugins` found a config file at the resolved path that could not be read, parsed or env-substituted, so it refuses (exit 1) rather than inventory the DEFAULT `plugins:` block (default dir and trust policy), which would describe a directory other than the one the deployment configures. The default block is used only when no config file exists at that path (a bare inventory).

## How to fix it

Fix config.yaml so it parses (run `busbar --validate` to see the error) and re-run `--list-plugins`, or point `--config` at the right file.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
