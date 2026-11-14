---
title: "BUSBAR-3404: --migrate-config refused the file"
description: "What Busbar error BUSBAR-3404 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3404
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3404: --migrate-config failed: <reason>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3404
```

## What it means

The old config could not be converted mechanically: it is not valid YAML, it has a shape no busbar release accepted, or it carries a value the migration cannot carry forward without guessing. The reason follows the code. Nothing was printed to stdout, so no half-migrated config can be deployed by accident.

## How to fix it

Fix the reason the message names in the OLD file (or capture the setting by hand), then run the migration again. docs/migration-1-6.md lists every key the migration rewrites.

## Example

```text
busbar --migrate-config not-yaml.txt
```

Busbar reports:

```text
BUSBAR-3404: --migrate-config failed: config is not a YAML mapping. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3404
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
