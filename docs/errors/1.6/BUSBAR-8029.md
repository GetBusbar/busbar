---
title: "BUSBAR-8029: A plugin instance's scheduled tick failed"
description: "What Busbar error BUSBAR-8029 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8029
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

busbar drives the tick of each secret and auth plugin instance that asks for one (its own token refresh or version watch). A tick answered neither ready nor pending (it failed, faulted or timed out). The schedule does not stop: the tick is retried with a jittered backoff (1 second doubling to 60 seconds) until it succeeds or the instance closes. Reported on the first failure and then at most once a minute per instance.

## How to fix it

Check the plugin's own log lines for the instance named. A tick that keeps failing usually means the plugin cannot reach the service it refreshes against.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
