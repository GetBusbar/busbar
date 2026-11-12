---
title: "BUSBAR-3128: A reference names a provider that is not defined or speaks the wrong protocol"
description: "What Busbar error BUSBAR-3128 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3128
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3128: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3128
```

## What it means

config.yaml (or a plane section) names a provider that providers.yaml and `providers:` do not define, or one whose protocol the referencing plane does not speak.

## How to fix it

Define the provider, fix the spelling, or point the reference at a provider of the right protocol; the message lists the valid choices.

## Example

```text
models:
  gpt-4o: { provider: openai-eu }   # not in providers.yaml
```

Busbar reports:

```text
BUSBAR-3128: provider 'openai-eu' referenced in config.yaml not found in providers.yaml. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3128
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
