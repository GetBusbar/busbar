---
title: "BUSBAR-3126: A provider names a protocol this build does not speak"
description: "What Busbar error BUSBAR-3126 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3126
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3126: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3126
```

## What it means

A provider's `protocol:` is not one this binary carries: it is misspelled, or the build has no plane that speaks it.

## How to fix it

Use one of the protocols the message lists, or run a build that carries the plane for it.

## Example

```text
providers:
  claude:
    protocol: antropic
```

Busbar reports:

```text
BUSBAR-3126: provider 'claude' has unknown protocol 'antropic': must be one of: anthropic, bedrock, cohere, gemini, openai, responses. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3126
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
