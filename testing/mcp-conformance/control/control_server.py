"""Control MCP server.

This is the REFERENCE the battery is validated against. It is built on the
pinned official Python SDK (mcp==2.0.0), which is the first official SDK
release implementing the modern stateless revision 2026-07-28.

It is deliberately boring. It exists to exercise the protocol surface the
battery probes, not to be interesting:

  * tools/list           two tools, deterministic order, one with outputSchema
  * tools/call           success, tool-execution error (isError), unknown tool
  * resources/list       one static resource
  * resources/read       text content
  * prompts/list         one prompt with an argument
  * prompts/get          returns a message
  * server/discover      supplied by the SDK

Run:  python control_server.py            (stdio)
      python control_server.py --http PORT (streamable http)

Nothing in the battery knows this file exists beyond the launch command it is
given on the command line. Pointing the battery at a different implementation
is a configuration change, not a code change.
"""

from __future__ import annotations

import sys

from mcp.server.mcpserver import MCPServer
from mcp.types import TextContent

server = MCPServer(
    name="control-reference-server",
    version="1.0.0",
    instructions="Control server for the independent MCP conformance battery.",
)


@server.tool(
    name="echo",
    title="Echo",
    description="Returns the string it was given.",
)
def echo(text: str) -> str:
    """Echo the supplied text back to the caller."""
    return text


@server.tool(
    name="add",
    title="Add",
    description="Adds two integers and returns the sum.",
)
def add(a: int, b: int) -> int:
    """Add two integers."""
    return a + b


@server.tool(
    name="always_fails",
    title="Always Fails",
    description="Always returns a tool execution error, never a protocol error.",
)
def always_fails() -> str:
    """Raise a tool-execution error so the SDK reports isError: true."""
    raise ValueError("deliberate tool execution failure")


@server.resource("file:///control/greeting.txt", name="greeting", mime_type="text/plain")
def greeting() -> str:
    """A single static text resource."""
    return "hello from the control server"


@server.prompt(name="summarize", description="Summarize the supplied text.")
def summarize(text: str) -> list[TextContent]:
    """Return a single-message prompt."""
    return [TextContent(type="text", text=f"Please summarize: {text}")]


def main() -> None:
    argv = sys.argv[1:]
    if argv and argv[0] == "--http":
        # Streamable HTTP, used by the official conformance suite, which only
        # speaks HTTP (it has no stdio driver).
        import anyio

        port = int(argv[1]) if len(argv) > 1 else 8931
        anyio.run(
            lambda: server.run_streamable_http_async(host="127.0.0.1", port=port)
        )
    else:
        server.run(transport="stdio")


if __name__ == "__main__":
    main()
