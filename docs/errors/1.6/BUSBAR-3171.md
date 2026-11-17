---
title: "BUSBAR-3171: A reserved configuration key was written"
description: "What Busbar error BUSBAR-3171 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3171
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3171: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3171
```

## What it means

A key busbar reserves or has retired was written in config.yaml or in an admin configuration publication. It is refused by name before the document is read, rather than with the generic unknown-field error, so the reason and the remedy are stated. Another unknown key keeps the generic error.

## How to fix it

Remove the key the message names. For `plugins.trust.operator`: 1.6.0 operator plugins must be first-party signed, so there is no operator trust setting to write.

## Example

```text
plugins:
  trust:
    operator: my-publisher
```

Busbar reports:

```text
BUSBAR-3171: plugins.trust.operator: reserved; 1.6.0 operator plugins must be first-party signed (Q13). See https://getbusbar.com/docs/1.6/errors/BUSBAR-3171
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
