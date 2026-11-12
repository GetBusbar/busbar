---
title: "BUSBAR-3102: A model definition is invalid"
description: "What Busbar error BUSBAR-3102 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3102
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3102: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3102
```

## What it means

An entry under `models:` names a provider that is not defined, or sets a per-model value outside its range: `default_max_tokens`, `max_concurrent` or `max_requests` of 0, an `attempt_timeout_ms` of 0 or above the 30-year ceiling, an empty `upstream_model`, or a `context_max` that two pools declare differently. The message names the model and the field.

## How to fix it

Fix the named field under `models.<name>:`: point `provider:` at a provider defined in providers.yaml or `providers:`, use a positive value, or omit the field to take its default. Then run `busbar --validate`.

## Example

```text
models:
  gpt-4o:
    provider: openia     # typo: no such provider
```

Busbar reports:

```text
BUSBAR-3102: model 'gpt-4o' references unknown provider 'openia'. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3102
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
