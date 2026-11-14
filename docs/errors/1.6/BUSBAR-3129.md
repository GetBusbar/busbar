---
title: "BUSBAR-3129: A configuration section is not valid for this build"
description: "What Busbar error BUSBAR-3129 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3129
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3129: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3129
```

## What it means

A top-level section does not parse into its shape, its registry fails its own checks, or it configures a plane (such as `oauth_as:`) whose implementation this binary does not link. The message names the section and the reason.

## How to fix it

Fix the section as the message describes, or remove a section this build does not carry.

## Example

```text
oauth_as:
  issuer: https://busbar.example.com
```

Busbar reports:

```text
BUSBAR-3129: oauth_as: configured, but the authorization-server plane (busbar-core-oauth2) is not linked into this binary. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3129
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
