---
title: "BUSBAR-3162: A plugin instance runs with insecure_transport accepted"
description: "What Busbar error BUSBAR-3162 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3162
---

**Area:** Config (3xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

An instance's `insecure_transport` acceptance admits plaintext, unverified TLS or both to the destinations the line names. Anything sent to them, credentials included, can be read and altered by anyone who can intercept the network path. The acceptance is recorded as a `config.insecure_transport_accepted` audit row.

## How to fix it

Remove the instance's `insecure_transport` once the server offers verifiable TLS.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
