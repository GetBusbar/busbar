---
title: "BUSBAR-9201: A plane needs a transport protocol that no installed transport provides"
description: "What Busbar error BUSBAR-9201 means, why it happens, and how to fix it."
slug: docs/1.6/errors/BUSBAR-9201
---

**Area:** Boot & lifecycle (9xxx) · **Severity:** fatal · **Since:** 1.6.0

## Message

```text
BUSBAR-9201: plane `<plane>` needs a transport of kind `transport` that provides the protocol `<transport>`, and none is installed or admitted; install a transport plugin that provides `<transport>`. See https://getbusbar.com/docs/1.6/errors/BUSBAR-9201
```

## What it means

A plane serves on a transport protocol (the admin plane serves on `http`, for example). Busbar itself provides no transport: every protocol comes from a plugin of kind `transport`, linked into the build or installed in `plugins.dir` and admitted at boot. No installed or admitted transport provides the protocol the message names, so the plane could never receive a request, and busbar refused to start rather than serve without it. This describes the deployment's installed plugins, not a fault in the binary. Nothing was served; the process exited with status 2.

## How to fix it

Install a transport plugin that provides the protocol the message names (a signed plugin of kind `transport` in `plugins.dir`), then restart. `busbar --list-plugins` lists the installed plugins and whether each one was admitted.

## Example

```text
busbar --config /etc/busbar/config.yaml
```

Busbar reports:

```text
BUSBAR-9201: plane `admin` needs a transport of kind `transport` that provides the protocol `http`, and none is installed or admitted; install a transport plugin that provides `http`. See https://getbusbar.com/docs/1.6/errors/BUSBAR-9201
```

---

[All error codes](/docs/1.6/errors/) · This page is generated from the Busbar source; do not edit it by hand.
