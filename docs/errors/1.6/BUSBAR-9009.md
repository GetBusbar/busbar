---
title: "BUSBAR-9009: Shutdown-signal handler not installed (that signal won't trigger graceful drain)"
description: "What Busbar error BUSBAR-9009 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9009
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A graceful-shutdown signal handler (SIGINT/ctrl_c, SIGTERM on unix, or CTRL_CLOSE/CTRL_SHUTDOWN on Windows) failed to register. busbar fails soft — that one branch parks forever so the others still trigger the drain — but a stop delivered ONLY via the failed signal will kill the process without draining in-flight requests.

## How to fix it

Investigate the logged registration error (an unusual sandbox or signal-handling environment). Other shutdown signals still drain; if the affected signal is your deployment's stop path, restart in an environment where it can register.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
