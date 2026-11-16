---
title: "BUSBAR-3124: A provider URL targets a blocked cloud-metadata host"
description: "What Busbar error BUSBAR-3124 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3124
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3124: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3124
```

## What it means

A provider's `base_url`, `base_url` + `path`, `base_url` + `path_base` or `token_url` resolves to a cloud-metadata (IMDS) endpoint on `security.blocked_metadata_hosts`. Busbar would send credentials there, so it refuses the configuration.

## How to fix it

Point the provider at its real API host. No setting admits a cloud-metadata host (BUSBAR-3136), so do not try to allow-list it; if the credential is for a cloud API, use that platform's workload identity.

## Example

```text
providers:
  internal:
    base_url: http://169.254.169.254
```

Busbar reports:

```text
BUSBAR-3124: provider 'internal' base_url 'http://169.254.169.254' targets a blocked cloud-metadata host '169.254.169.254' (cloud-metadata/IMDS endpoints are denied; ...). See https://getbusbar.com/docs/1.6/errors/BUSBAR-3124
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
