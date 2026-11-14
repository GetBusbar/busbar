---
title: "BUSBAR-3123: A provider definition is invalid"
description: "What Busbar error BUSBAR-3123 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3123
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3123: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3123
```

## What it means

A provider's settings cannot work: a health interval or timeout of 0 or above its ceiling, an `error_map` class that does not exist, a `path` or `path_base` that does not begin with `/`, or an option the provider's protocol does not take.

## How to fix it

Fix the field the message names under `providers.<name>:`; docs/providers.md documents every provider field.

## Example

```text
providers:
  openai:
    base_url: https://api.openai.com
    path: v1/chat/completions
```

Busbar reports:

```text
BUSBAR-3123: provider 'openai' path 'v1/chat/completions' must begin with '/': a path override is appended to base_url verbatim, so a path that does not start with '/' fuses into the host (e.g. base_url + 'v1/chat/completions') and can redirect signed traffic to an attacker-controlled host. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3123
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
