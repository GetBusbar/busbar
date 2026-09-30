# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# A REAL, PINNED PYTHON MCP SDK SERVER (py/requirements-server.txt, revision 2025-06-18) for busbar
# to call as an upstream over Streamable HTTP at /mcp.
#
#   python servers/py_server.py <port>
#
# One tool, `echo` (text -> the same text). Knows nothing about busbar.

import sys

from mcp.server.fastmcp import FastMCP


def main(port: int) -> None:
    server = FastMCP("compat-echo", host="127.0.0.1", port=port, streamable_http_path="/mcp")

    @server.tool()
    def echo(text: str) -> str:
        """Echo the text back."""
        return text

    print(f"ready {port}", flush=True)
    server.run(transport="streamable-http")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: py_server.py <port>", file=sys.stderr)
        sys.exit(2)
    main(int(sys.argv[1]))
