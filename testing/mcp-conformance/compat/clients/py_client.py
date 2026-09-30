# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# A REAL, PINNED PYTHON MCP SDK CLIENT (py/requirements-client.txt) driven against busbar's
# endpoint over Streamable HTTP.
#
#   python clients/py_client.py <endpoint-url>
#
# The SDK negotiates its own latest revision in initialize. Prints one JSON line; exit 0 only when
# every check passed.

import asyncio
import json
import sys

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


async def main(endpoint: str) -> int:
    checks: dict[str, bool] = {}
    failures: list[str] = []

    def check(name: str, ok: bool, detail: str = "failed") -> None:
        checks[name] = bool(ok)
        if not ok:
            failures.append(f"{name}: {detail}")

    try:
        async with streamablehttp_client(endpoint) as (read, write, get_session_id):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                check("initialize", True)
                check(
                    "negotiated a session revision",
                    init.protocolVersion in ("2025-11-25", "2025-06-18"),
                    str(init.protocolVersion),
                )
                sid = get_session_id()
                check("session named", isinstance(sid, str) and len(sid) == 32, str(sid))
                tools = await session.list_tools()
                check("tools/list", isinstance(tools.tools, list))
                await session.send_ping()
                check("ping", True)
                callable_tool = next(
                    (t for t in tools.tools if not (t.inputSchema or {}).get("required")), None
                )
                if callable_tool is not None:
                    result = await session.call_tool(callable_tool.name, {})
                    check("tools/call", result is not None and isinstance(result.content, list))
    except Exception as e:  # noqa: BLE001 - the report names whatever failed
        failures.append(f"exception: {e!r}")

    ok = not failures and bool(checks)
    print(json.dumps({"peer": "python-sdk client", "direction": "client -> busbar", "ok": ok,
                      "checks": checks, "failures": failures}))
    return 0 if ok else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: py_client.py <endpoint-url>", file=sys.stderr)
        sys.exit(2)
    sys.exit(asyncio.run(main(sys.argv[1])))
