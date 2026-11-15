---
title: "BUSBAR-8027: A plane member's upstream credential lapsed or was revoked at its source"
description: "What Busbar error BUSBAR-8027 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-8027
---

**Area:** Governance & cost (8xxx) · **Severity:** actionable · **Since:** 1.6.0

## What it means

A plane member's upstream credential is no longer presented, so every hop on the member is refused (credential_unavailable; for an A2A member, BUSBAR-7013). Cause lease-expired: its lease_ttl_ms ran out with no successful refresh (reported when the lease ends, whether or not a hop arrives). Cause revoked-at-source: the source answered not-found or permission-denied twice, one second apart, so busbar dropped the credential at once instead of riding out an outage. Reported once per lapse and audited as upstream_credential.refresh, rejected. Refreshes continue; the first that succeeds presents the credential again.

## How to fix it

For revoked-at-source, this is expected after deleting the secret or removing busbar's access to it; restore it to resume. For lease-expired, see the BUSBAR-8026 lines for the member: they name the source and the error. A longer lease_ttl_ms rides out longer outages; a shorter one revokes faster.

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
