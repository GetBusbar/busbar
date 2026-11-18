---
title: "BUSBAR-2059: An amendment record names a class this build does not know"
description: "What Busbar error BUSBAR-2059 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-2059
---

**Area:** Audit chain (2xxx) · **Severity:** actionable · **Since:** 1.6.0

## Message

```text
BUSBAR-2059: unknown amendment class `<word>`: written by a newer busbar, or the chain is damaged; if every node runs this release, treat it as tampering (upgrade: https://getbusbar.com/download). See https://getbusbar.com/docs/1.6/errors/BUSBAR-2059
```

## What it means

At boot the amendment chain was read back from the store and a record names an amendment class (the word after its hashes) that this build does not know. The record is never taken into the amendment run, and neither is anything that links after it: they are set aside and named in the restart findings. Boot continues. In a rolling upgrade a newer release writes classes an older one cannot read; otherwise the record was damaged or written by something that is not busbar.

## How to fix it

If any node in the deployment runs a newer busbar, upgrade this node (https://getbusbar.com/download). If every node runs this release, treat the amendment chain as tampered until explained: capture the store for forensic review before it is overwritten, then restore from a trusted backup.

## Example

```text
a 1.6.0 node restarts over an amendment chain a later release extended
```

Busbar reports:

```text
BUSBAR-2059: unknown amendment class `content`: written by a newer busbar, or the chain is damaged; if every node runs this release, treat it as tampering (upgrade: https://getbusbar.com/download). See https://getbusbar.com/docs/1.6/errors/BUSBAR-2059
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
