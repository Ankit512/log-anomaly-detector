"""server.py — the MCP wiring: tool schemas + dispatch over stdio.

This is the ONLY module that imports the mcp SDK (installed from
requirements-mcp.txt). The actual work lives in tools.py so it stays testable
without the SDK and without the network. Adding a tool = one entry in TOOLS.

Launch:  python -m itsoc_mcp   (speaks MCP over stdio)
Backend: the local console must be running — `python3 console/serve.py`
Config:  ITSOC_BASE_URL (default http://127.0.0.1:8765),
         ITSOC_MCP_TRUSTED_LOCAL=1 to return raw (unredacted) log text.
"""

import asyncio
import json

from .client import ApiClient
from . import tools


# --- tool registry --------------------------------------------------------
# Each entry: name, description, JSON-Schema for arguments, and a handler that
# receives (client, arguments) and returns a JSON-serializable dict. Stage 2
# appends the remaining six read-only tools here.
TOOLS = [
    {
        "name": "analyze_log",
        "description": (
            "Run the project's existing analysis over a local log file OR an "
            "http(s) URL and return a run summary (run_id, severity counts, "
            "lines parsed/unparsed, unrecognized flag, detector sha256). Verdicts "
            "are rule-owned by the frozen detector; this only relays them. An "
            "unrecognized format returns '0 lines parsed', never a fake all-clear."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "source": {
                    "type": "string",
                    "description": "A local file path or an http(s) URL to analyze.",
                },
                "compare": {
                    "type": "boolean",
                    "description": "Also run the rules-vs-LLM comparison pass.",
                    "default": False,
                },
            },
            "required": ["source"],
        },
        "handler": lambda client, args: tools.analyze_log(
            client, source=args.get("source", ""),
            compare=bool(args.get("compare", False))),
    },
]

_BY_NAME = {t["name"]: t for t in TOOLS}


def build_server(client=None):
    """Construct the MCP Server with tools registered. `client` is injectable so
    a harness can supply a fake; production uses a real ApiClient (ITSOC_BASE_URL)."""
    from mcp.server import Server           # imported lazily so tools.py stays SDK-free
    import mcp.types as types

    client = client or ApiClient()
    server = Server("itsoc-mcp")

    @server.list_tools()
    async def list_tools():
        return [types.Tool(name=t["name"], description=t["description"],
                           inputSchema=t["inputSchema"]) for t in TOOLS]

    @server.call_tool()
    async def call_tool(name, arguments):
        tool = _BY_NAME.get(name)
        if tool is None:
            payload = {"ok": False, "error": f"unknown tool: {name}"}
        else:
            # Tools do blocking urllib I/O; run off the event loop.
            payload = await asyncio.to_thread(tool["handler"], client, arguments or {})
        return [types.TextContent(type="text", text=json.dumps(payload, indent=2))]

    return server


async def _amain():
    from mcp.server.stdio import stdio_server

    server = build_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream,
                         server.create_initialization_options())


def main():
    asyncio.run(_amain())


if __name__ == "__main__":
    main()
