---
title: "BUSBAR-3163: An insecure_transport acceptance is invalid"
description: "What Busbar error BUSBAR-3163 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-3163
---

**Area:** Config (3xxx) · **Severity:** fatal · **Since:** 1.6.0

## What it means

An `insecure_transport` block was refused at load: it is not a map, its `accept` list is empty, repeated or names an unknown value (the values are `plaintext` and `unverified_tls`), it names a key other than `accept` and `reason`, its `reason` is missing or unusable, or none of the instance's declared endpoints needs the acceptance. The line names the path and the key.

## How to fix it

Fix or delete the block. `accept` takes `plaintext`, `unverified_tls` or both, once each, with a `reason`; an acceptance an instance does not need is refused, so remove it.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
