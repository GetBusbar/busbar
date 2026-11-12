---
title: "BUSBAR-3402: --migrate-config could not read the file it was given"
description: "What Busbar error BUSBAR-3402 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3402
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3402: cannot read '<path>': <error>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3402
```

## What it means

The old config file named to `--migrate-config` could not be read: it does not exist, it is not readable by this user, or it is not UTF-8 text. The operating system's reason follows the path. Nothing was migrated.

## How to fix it

Check the path and its permissions, then run the migration again.

## Example

```text
busbar --migrate-config /etc/busbar/old.yaml
```

Busbar reports:

```text
BUSBAR-3402: cannot read '/etc/busbar/old.yaml': No such file or directory (os error 2). See https://getbusbar.com/docs/1.6/errors/BUSBAR-3402
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
