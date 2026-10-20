#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# THE CONTROL PEER: a WebSocket echo server on the Python `websockets` package (an independent
# implementation busbar does not use), so the control leg proves the harness grades a known peer
# green BEFORE any busbar verdict is believed. It claims what the suite claims, RFC 6455 alone: no
# permessage-deflate (Autobahn scores groups 12/13 UNIMPLEMENTED, as for busbar), no message size
# ceiling (Autobahn's 9.x cases send up to 16 MiB), and no keepalive pings of its own.
#
# Prints `REFERENCE_PORT=<port>` once bound.

import asyncio

from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed


async def echo(ws):
    try:
        async for message in ws:
            await ws.send(message)
    except ConnectionClosed:
        pass


async def main():
    async with serve(
        echo,
        "127.0.0.1",
        0,
        compression=None,
        max_size=None,
        ping_interval=None,
    ) as server:
        port = server.sockets[0].getsockname()[1]
        print(f"REFERENCE_PORT={port}", flush=True)
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
