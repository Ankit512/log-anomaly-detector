# Publishing `itsoc-mcp` — DRAFT (human-gated)

This is a **draft** to make the server discoverable. Nothing here has been
submitted or uploaded. **Do not** run `twine`/PyPI upload, open a registry PR, or
push to any external repo without a human decision — those steps are intentionally
left to a person.

## Server identity

- **Name:** `itsoc-mcp`
- **One-line description:** Read-only MCP server exposing a local log-analysis
  backend's existing analysis to MCP clients — client of the local API, computes
  no verdicts, redacted-by-default egress.
- **Homepage:** https://github.com/Ankit512/log-anomaly-detector
- **License:** MIT
- **Transport:** stdio
- **Tools (all read-only):** `analyze_log`, `list_runs`, `get_findings`,
  `get_evidence`, `explain_finding`, `export_run`, `threat_intel_lookup`

## Install command (once published)

```sh
uvx itsoc-mcp        # or: pipx run itsoc-mcp
```

> **Precondition, stated honestly:** the server delegates to repo siblings
> (`console/redact.py` for the egress guard; `threat_intel/` for the offline
> lookup), so today it must run **from the repo root** (`python -m itsoc_mcp`).
> A bare `uvx itsoc-mcp` outside the repo will fail **closed** (it cannot leak).
> Publishing a genuinely standalone distribution first requires vendoring
> `console/redact.py` into the package and guarding `threat_intel_lookup` — a
> deliberate, human-approved change, not done here.

## Paste-ready MCP client registration (stdio)

For Claude Desktop (`claude_desktop_config.json`) or Claude Code (`.mcp.json`).
Replace `/ABSOLUTE/PATH/TO/log-analyzer` with the repo root:

```json
{
  "mcpServers": {
    "itsoc": {
      "command": "python",
      "args": ["-m", "itsoc_mcp"],
      "cwd": "/ABSOLUTE/PATH/TO/log-analyzer",
      "env": {
        "ITSOC_BASE_URL": "http://127.0.0.1:8765"
      }
    }
  }
}
```

Optional `env` additions: `"ITSOC_MCP_TRUSTED_LOCAL": "1"` to return raw
(unredacted) evidence/export on a trusted local machine, and
`"ITSOC_STIX_BUNDLE": "/path/to/bundle.json"` for `threat_intel_lookup`. The
backend (`python3 console/serve.py`) must be running.

## Pre-submission checklist (for the human)

- [ ] Confirm the LICENSE copyright holder name (currently "Ankit Kumar").
- [ ] Decide whether to vendor `console/redact.py` for a standalone release, or
      publish as a repo-local server only.
- [ ] `python -m build` from `itsoc_mcp/` and verify the wheel entry point.
- [ ] `python3 itsoc_mcp/test_mcp.py` green.
- [ ] Only then: PyPI upload and/or MCP-registry submission.
