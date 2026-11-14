---
title: "BUSBAR-3101: A registration is named with a reserved word"
description: "What Busbar error BUSBAR-3101 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3101
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3101: a <noun> may not be named `<name>` (reserved in `<section>:`). See https://getbusbar.com/docs/1.6/errors/BUSBAR-3101
```

## What it means

Inside a section that registers named entries (`pools:`, `tools:`, `agents:`, `streams:`, `decisions:` and the rest), a few keys belong to Busbar: the section-level `hooks`, `upstream_credentials` and `usage_observations`, and the core-owned settings `pools`, `breaker`, `on_exhausted`, `affinity`, `gates`, `tier`, `repeatable`, `work`, `timeout`, `rate_card` and `fees`. A registration that takes one of those names cannot be told apart from the setting, so the configuration is refused at `--validate` and at startup.

## How to fix it

Rename the registration; any name not on the list works. Then run `busbar --validate`. The reserved names and what each is for are tabled in docs/configuration.md (Reserved names).

## Example

```text
pools:
  hooks:            # a pool named `hooks`
    members: [gpt-4o]
```

Busbar reports:

```text
BUSBAR-3101: a pool may not be named `hooks` (reserved in `pools:`). See https://getbusbar.com/docs/1.6/errors/BUSBAR-3101
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
