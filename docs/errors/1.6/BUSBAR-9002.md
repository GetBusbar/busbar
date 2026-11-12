---
title: "BUSBAR-9002: TLS accept loop failing persistently (backing off)"
description: "What Busbar error BUSBAR-9002 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9002
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A TLS listener's accept loop is failing persistently — commonly file-descriptor exhaustion — so busbar backs off before retrying rather than spin hot on the error. On unix each of the N data-plane workers runs its own accept loop, so the warning can fire from one worker or from several at once. The warning is already rate-limited by the backoff delay, so each loop fires at a human cadence, not per failed accept.

## How to fix it

Investigate the accept failure — most often the process fd limit (raise `ulimit -n` / the systemd `LimitNOFILE`) or a resource leak holding sockets open. Each listener keeps retrying with backoff and recovers on its own once accepts succeed.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
