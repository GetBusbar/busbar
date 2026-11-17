---
title: "BUSBAR-2049: The audit notary could not stamp a page (lines stay durable and linked)"
description: "What Busbar error BUSBAR-2049 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-2049
---

**Area:** Audit chain (2xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

The background audit notary signs the newest audit line fingerprint every audit.seal_every milliseconds, and that one stamp vouches for every line before it. It could not: its signer failed, timed out or panicked three times in a row (reason=signer, signer_panic), the store refused or did not confirm the staged stamp (reason names the journal error), the journal failed for this process, or the notary task itself stopped (reason=panic). Requests are not affected and every line is still durable and linked; only the stamp is missing. Stamping resumes on its own after a transient failure, with a capped backoff of up to one second, and an Info line follows the first success. If the notary stopped for good, the next busbar process on this host seals the unstamped tail after restart or records a chain break.

## How to fix it

Check the field reason. For signer: check the audit signing key or KMS secret plugin. For a journal error: check the store health. For panic or signer_panic: restart the process when convenient and report the log; until then lines are unstamped but durable.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
