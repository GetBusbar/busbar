---
title: "BUSBAR-8023: A stored recoverable credential opens under neither at-rest key (it does not authenticate)"
description: "What Busbar error BUSBAR-8023 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8023
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A recoverable credential (a signed-request secret) is stored sealed under an at-rest key whose kid does not match the key derived from auth.signing_key on this node, or its row was altered. It answers as an unknown credential: requests signed with it are refused. The refusal is audited once per kid.

## How to fix it

Give every node that shares the store the same auth.signing_key, and reload. Rotating auth.signing_key retires the credentials sealed under the old one: re-mint them.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
