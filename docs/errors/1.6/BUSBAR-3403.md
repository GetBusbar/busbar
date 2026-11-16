---
title: "BUSBAR-3403: The retired migration command could not resolve its working directory — RETIRED"
description: "What Busbar error BUSBAR-3403 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3403
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

> **Retired.** Busbar no longer reports this code. The page stays so an old log line still resolves; the code is never reused.

## What it means

RETIRED. Nothing emits this code: the retired migration command is gone in 1.6.0; the first boot of a 1.5.5 config migrates it in place and keeps a `config.yaml.1.5.5` backup beside it. The number is kept so a log line from a pre-release build still resolves to this page.

## How to fix it

Nothing emits this code. Start busbar on the 1.5.5 config.yaml; the boot migrates it. See docs/migration-1.6.md.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
