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
    {
        "name": "list_runs",
        "description": (
            "List saved analysis runs from the backend's run history (read-only). "
            "Returns run_id, label, finding count, and the current run. Empty when "
            "there are no runs — never a fabricated entry."),
        "inputSchema": {"type": "object", "properties": {}},
        "handler": lambda client, args: tools.list_runs(client),
    },
    {
        "name": "get_findings",
        "description": (
            "Filtered findings for the ACTIVE run, with rule-owned severity, "
            "rule_id, and derived MITRE tags. Filter by severity/rule/host and "
            "limit. Host/title are redacted by default (entity-bearing text). "
            "A non-current run_id is an honest error — this server does not switch "
            "the active run."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_id": {"type": "string",
                           "description": "Optional; must be the active run. Omit to use it."},
                "severity": {"type": "string",
                             "description": "CRITICAL|HIGH|MEDIUM|LOW filter (exact)."},
                "rule": {"type": "string", "description": "rule_id substring filter."},
                "host": {"type": "string", "description": "host substring filter."},
                "limit": {"type": "integer", "description": "max findings (default 50).",
                          "default": 50},
            },
        },
        "handler": lambda client, args: tools.get_findings(
            client, run_id=args.get("run_id", ""), severity=args.get("severity", ""),
            rule=args.get("rule", ""), host=args.get("host", ""),
            limit=args.get("limit", 50)),
    },
    {
        "name": "get_evidence",
        "description": (
            "Real evidence lines + rule predicate + timeline for ONE finding in the "
            "active run. Raw log lines and timeline labels pass through the "
            "console/redact.py egress choke point and are REDACTED by default; set "
            "ITSOC_MCP_TRUSTED_LOCAL=1 for raw text. Evidence is verbatim source "
            "(masked), never fabricated."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string",
                               "description": "Finding id from get_findings."},
                "run_id": {"type": "string", "description": "Optional; must be the active run."},
            },
            "required": ["finding_id"],
        },
        "handler": lambda client, args: tools.get_evidence(
            client, finding_id=args.get("finding_id", ""), run_id=args.get("run_id", "")),
    },
    {
        "name": "explain_finding",
        "description": (
            "Advisory LLM explanation for ONE finding via the existing /api/explain "
            "endpoint. The explanation is ADVISORY only — it never changes, "
            "suppresses, or escalates the rule verdict. Prose is redacted by "
            "default. An unreachable model is an honest error, never a made-up "
            "explanation."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string",
                               "description": "Finding id from get_findings."},
                "run_id": {"type": "string", "description": "Optional; must be the active run."},
            },
            "required": ["finding_id"],
        },
        "handler": lambda client, args: tools.explain_finding(
            client, finding_id=args.get("finding_id", ""), run_id=args.get("run_id", "")),
    },
    {
        "name": "export_run",
        "description": (
            "Export the ACTIVE run via /api/export (csv|html|xml|json|md). When "
            "idle the backend returns 409 and this relays it honestly — never an "
            "empty file. The export carries raw log text, so content is withheld by "
            "default (size + sha256 returned); set ITSOC_MCP_TRUSTED_LOCAL=1 to "
            "receive it inline."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "format": {"type": "string", "enum": list(tools.EXPORT_FORMATS),
                           "description": "Export format.", "default": "html"},
                "run_id": {"type": "string", "description": "Optional; must be the active run."},
            },
        },
        "handler": lambda client, args: tools.export_run(
            client, format=args.get("format", "html"), run_id=args.get("run_id", "")),
    },
    {
        "name": "threat_intel_lookup",
        "description": (
            "OFFLINE STIX->MITRE lookup for one IPv4 address, reusing the project's "
            "existing offline threat-intel code (no network egress). Match + "
            "severity come from threat_intel/threat_detector.py; MITRE tags are "
            "derived. No bundle configured -> honest n/a; no match -> honest "
            "'no match', never a fake all-clear. Bundle path via arg or "
            "ITSOC_STIX_BUNDLE."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IPv4 address to look up."},
                "bundle_path": {"type": "string",
                                "description": "Optional local STIX bundle path "
                                               "(overrides ITSOC_STIX_BUNDLE)."},
            },
            "required": ["ip"],
        },
        "handler": lambda client, args: tools.threat_intel_lookup(
            client, ip=args.get("ip", ""), bundle_path=args.get("bundle_path")),
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
