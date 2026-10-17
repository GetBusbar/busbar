"""Control MCP client.

The REFERENCE for the client half of the battery, built on the pinned official
Python SDK (mcp==2.0.0).

CONTRACT (the one thing the battery asks of any subject in its client role):

    argv[-1]  is a shell command that launches a stdio MCP server
    env MCP_TARGET_SERVER_COMMAND  carries the same command

    On start, connect to that server and do some ordinary work: discover,
    list tools, call a tool. Then exit.

MCP standardises the wire, not how a host is told which server to talk to, so
some contract of this shape is unavoidable. Everything the battery asserts is
observed from the SERVER side, so this program is not trusted to report on
itself; it only has to connect and do something.
"""

from __future__ import annotations

import anyio
import os
import shlex
import sys

from mcp.client import Client
from mcp.client.stdio import StdioServerParameters, stdio_client


def target_command() -> list[str]:
    raw = None
    if len(sys.argv) > 1:
        raw = sys.argv[-1]
    raw = os.environ.get("MCP_TARGET_SERVER_COMMAND", raw)
    if not raw:
        print("no target server command supplied", file=sys.stderr)
        raise SystemExit(2)
    return shlex.split(raw)


async def main() -> None:
    argv = target_command()
    params = StdioServerParameters(command=argv[0], args=argv[1:], env=dict(os.environ))

    # stdio_client(...) is itself the Transport (an async context manager
    # yielding the stream pair), so it is handed to Client directly.
    if True:
        async with Client(stdio_client(params), read_timeout_seconds=8.0) as client:
            # Ordinary work. Every step is allowed to fail: the battery is
            # observing the wire, not this program's return value.
            try:
                tools = await client.list_tools()
                names = [t.name for t in getattr(tools, "tools", [])]
                print(f"tools: {names}", file=sys.stderr)
            except Exception as exc:  # noqa: BLE001
                print(f"list_tools failed: {exc!r}", file=sys.stderr)
                names = []

            if "echo" in names:
                try:
                    await client.call_tool("echo", {"text": "battery"})
                except Exception as exc:  # noqa: BLE001
                    print(f"call_tool failed: {exc!r}", file=sys.stderr)

            for coro, label in (
                (client.list_resources(), "list_resources"),
                (client.list_prompts(), "list_prompts"),
            ):
                try:
                    await coro
                except Exception as exc:  # noqa: BLE001
                    print(f"{label} failed: {exc!r}", file=sys.stderr)


if __name__ == "__main__":
    try:
        anyio.run(main)
    except Exception as exc:  # noqa: BLE001
        # A hostile peer is expected to break us sometimes. Exiting non-zero is
        # a legitimate outcome and the battery records it rather than failing.
        print(f"control client terminated: {exc!r}", file=sys.stderr)
        raise SystemExit(1)
