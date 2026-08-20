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

> **Standalone, stated honestly:** the package is self-contained and runs from a
> bare `uvx itsoc-mcp` install (verified in a clean out-of-repo venv). Two caveats:
> (1) the **backend still runs separately** — `python3 console/serve.py`, reachable
> at `ITSOC_BASE_URL`; "standalone" means no repo checkout for the *MCP package*,
> not a backend-free server. (2) `threat_intel_lookup` reuses the repo's
> `threat_intel/` package and so **fails closed** with an honest "unavailable"
> message in a bare install (never a fake match); run from the repo to use it. The
> egress guard is never weaker standalone — redaction uses `console/redact.py`
> in-repo and a drift-guarded verbatim vendored mirror otherwise.

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

The block above (`python -m itsoc_mcp`, `cwd` = repo root) gives the **full** tool
set. A **standalone** registration also works — `"command": "uvx"`,
`"args": ["itsoc-mcp"]`, no `cwd` needed — with the single caveat that
`threat_intel_lookup` fails closed (offline-TI needs the repo). Everything else is
identical.

## Pre-submission checklist (for the human)

- [ ] Confirm the LICENSE copyright holder name (currently "Ankit Kumar").
- [ ] `python -m build` from `itsoc_mcp/` and verify the wheel entry point.
- [ ] `python3 itsoc_mcp/test_mcp.py` green (includes the redaction drift-guard).
- [ ] Confirmed: installs + runs in a clean out-of-repo venv, redaction masks by
      default via the vendored mirror, `threat_intel_lookup` fails closed.
- [ ] Only then: PyPI upload and/or MCP-registry submission.
