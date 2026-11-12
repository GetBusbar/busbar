---
title: "BUSBAR-3114: A role binding is invalid"
description: "What Busbar error BUSBAR-3114 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3114
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3114: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3114
```

## What it means

An entry under `auth.role_bindings` names a module that is in neither auth chain, a role that shadows the reserved operator principal, an unknown admin scope or admin verb, a grant kind no installed plane declares, or a group that does not exist. A binding like that grants nothing, or grants something other than what it says.

## How to fix it

Fix the binding the message names; the message prints the exact YAML to add where a module or group is missing.

## Example

```text
auth:
  role_bindings:
    oidc:
      engineers: { group: eng }   # no group `eng`
```

Busbar reports:

```text
BUSBAR-3114: role_bindings.oidc.engineers names group 'eng', which does not exist.
Paste this under groups and set its limits:

  eng:
    limits:
      - { requests: 0, per: minute }
. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3114
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
