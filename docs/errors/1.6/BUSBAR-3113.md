---
title: "BUSBAR-3113: An auth policy or key lifetime setting is invalid"
description: "What Busbar error BUSBAR-3113 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3113
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-3113: <detail>. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3113
```

## What it means

A setting under `auth:` that governs minted keys cannot hold: a duration that does not parse, a per-role mint ceiling wider than the deployment-wide policy, a delegated admin scope that does not parse, or a browser-login method without a `public_url:` to build its redirect URLs.

## How to fix it

Fix the named setting: durations are written like `30d` or `12h`, per-role ceilings must stay within `auth.policy`, and a browser login needs top-level `public_url: https://<busbar-host>`.

## Example

```text
auth:
  policy:
    binding_modes: [time-bound]
    mint_ceilings:
      ci: { binding_modes: [both] }
```

Busbar reports:

```text
BUSBAR-3113: auth.policy.mint_ceilings.ci.binding_modes names 'both', which auth.policy.binding_modes does not allow; a per-role ceiling cannot widen the deployment-wide binding modes. See https://getbusbar.com/docs/1.6/errors/BUSBAR-3113
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
