---
title: "BUSBAR-9007: Boot refused (fatal misconfiguration or startup error; process exits non-zero)"
description: "What Busbar error BUSBAR-9007 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9007
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** fatal · **Since:** 1.6.0

## What it means

The binary hit a fatal startup condition — a misconfiguration or other boot-time failure the process cannot serve past — so it printed a single-line reason to stderr and exited non-zero rather than a Rust panic backtrace. The specific reason is printed alongside this code. This is a deliberate refusal, not a crash.

## How to fix it

Read the printed reason, fix the underlying config/environment problem, and restart. `busbar --validate` reproduces most boot refusals without binding a listener.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
