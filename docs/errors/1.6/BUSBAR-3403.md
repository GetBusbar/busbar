---
title: "BUSBAR-3403: --migrate-config could not resolve its working directory"
description: "What Busbar error BUSBAR-3403 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3403
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3403: cannot resolve migration launch directory: <error>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3403
```

## What it means

The migration resolves relative paths (a providers file, a store path) against the directory busbar was launched from, as the old launcher did. The current directory could not be read (it was deleted or is not accessible), so nothing was migrated.

## How to fix it

Run the migration from an existing, readable directory, ideally the one the old deployment was launched from.

## Example

```text
cd /tmp/gone && rmdir /tmp/gone && busbar --migrate-config old.yaml
```

Busbar reports:

```text
BUSBAR-3403: cannot resolve migration launch directory: No such file or directory (os error 2). See https://getbusbar.com/docs/1.6/errors/BUSBAR-3403
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
