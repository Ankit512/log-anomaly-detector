# itsoc_mcp — a read-only MCP server over the local analysis backend

`itsoc_mcp` exposes this project's **existing** log-analysis capabilities as
[Model Context Protocol](https://modelcontextprotocol.io) tools, so an
MCP-capable agent (Claude Code / Claude Desktop) can drive them. It is an
**isolated sibling package**: it imports nothing from `anomaly_detector.py`,
changes no `/api/*` route, and adds no dependency to the core backend.

## What it is (and is not)

- **A client, not a brain.** Every tool proxies the already-running local backend
  (`http://127.0.0.1:8765` by default). This server computes **no verdicts**:
  severities, correlation, and rule verdicts are owned by the frozen deterministic
  detector on the backend. Tools relay; they never re-decide.
- **Read-only.** No tool writes, remediates, or acts. `analyze_log` starts an
  analysis (the one existing "write" the API offers) and `explain_finding`
  requests an **advisory** explanation via the existing endpoint — an explanation
  never changes, suppresses, or escalates a verdict.
- **Honest by construction.** Backend `null` / "0 lines parsed" / idle states are
  passed through verbatim — never a fabricated all-clear or an empty file.
- **Redacted by default.** Any field carrying raw log text is masked through the
  project's existing egress choke point (`console/redact.py`) before it leaves,
  **unless** you opt into a trusted local session (see below).

Every tool response carries a `provenance` block stating: verdicts are
deterministic/rule-owned, explanations are advisory, MITRE tags are derived (not
verdicts), plus the running detector's `detector_sha256`.

## Tools

| Tool | What it returns | Honesty notes |
|------|-----------------|---------------|
| `analyze_log(source, compare=False)` | Runs the existing analyze flow on a local path **or** an http(s) URL; returns `run_id` + summary (severity counts, lines parsed/unparsed, unrecognized flag, detector sha). | Unrecognized format → "0 lines parsed", explicitly **not** an all-clear. |
| `list_runs()` | Saved runs from run history, plus the current run. | Empty history is honestly empty. |
| `get_findings(run_id='', severity='', rule='', host='', limit=50)` | Filtered findings for the **active** run: rule-owned severity, `rule_id`, derived MITRE tags. | Host/title are redacted by default. A non-current `run_id` is an honest error (this server never switches the active run). |
| `get_evidence(finding_id, run_id='')` | Real evidence lines + rule predicate + timeline for one finding. | Raw lines and timeline labels are **redacted by default**. |
| `explain_finding(finding_id, run_id='')` | Advisory LLM explanation via `/api/explain`. | Advisory only; redacted by default; an unreachable model is an honest error. |
| `export_run(format, run_id='')` | Proxies `/api/export` (`csv\|html\|xml\|json\|md`). | Idle → honest 409 ("nothing to export yet"), never an empty file. Content carries raw log text, so it is **withheld by default** (real size + sha256 returned); set the trusted-local flag to receive it inline. |
| `threat_intel_lookup(ip, bundle_path=None)` | **Offline** STIX→MITRE lookup for one IPv4, reusing `threat_intel/` (match + severity from `threat_detector.py`, MITRE from the cached ATT&CK DB). No network egress. | No bundle configured → honest n/a; no match → honest "no match", not an all-clear. |

## Install

The core backend stays **stdlib-only** — do not install anything to run it. Install
the MCP SDK only if you want to run this server:

```sh
pip install -r itsoc_mcp/requirements-mcp.txt   # the `mcp` SDK, and nothing else
```

## Run

1. Start the backend (from the repo root), stdlib-only, no extra installs:

   ```sh
   python3 console/serve.py           # serves http://127.0.0.1:8765
   ```

2. Launch the MCP server over stdio (from the repo root):

   ```sh
   python -m itsoc_mcp
   ```

## Configuration (environment)

| Variable | Default | Purpose |
|----------|---------|---------|
| `ITSOC_BASE_URL` | `http://127.0.0.1:8765` | Where the local backend is listening. |
| `ITSOC_MCP_TRUSTED_LOCAL` | *(unset)* | Set to `1` to return **raw** (unredacted) log text and inline export content. Leave unset for any session an MCP client could relay off-machine — the default masks IPs, usernames, and known hosts. |
| `ITSOC_STIX_BUNDLE` | *(unset)* | Path to a local STIX bundle for `threat_intel_lookup`. Unset → the tool honestly reports "n/a — nothing to match against". |

## Register with an MCP client (stdio)

Paste into your MCP client config (e.g. Claude Desktop's
`claude_desktop_config.json`, or `.mcp.json` for Claude Code). Replace
`/ABSOLUTE/PATH/TO/log-analyzer` with the repo root:

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

To allow raw evidence/export on a trusted local machine, add
`"ITSOC_MCP_TRUSTED_LOCAL": "1"` (and optionally `"ITSOC_STIX_BUNDLE": "..."`) to
that `env` block. The backend (`python3 console/serve.py`) must be running.

## Tests

Network-free, no SDK, no ATT&CK cache required — the client is faked and the
offline mapper is stubbed:

```sh
python3 itsoc_mcp/test_mcp.py
```

It asserts each tool's shape, that `get_evidence`/`get_findings`/`explain_finding`
are **redacted by default** and raw only with `ITSOC_MCP_TRUSTED_LOCAL=1`, and
that idle/unrecognized/error states return honest errors, not empty payloads.

## Packaging & the standalone limitation (honest)

`pyproject.toml` builds an `itsoc-mcp` distribution with an `itsoc-mcp` console
script (`itsoc_mcp.server:main`) and pins `mcp>=1.0,<2` — MCP clients speak the
stable 1.x API; mcp 2.0 changed the server API. `python -m build` produces a wheel
whose entry point resolves.

The **supported way to run it is from the repo root** (`python -m itsoc_mcp`, or
the console script with the repo importable), because two tools delegate to repo
siblings on purpose rather than duplicating logic:

- `redaction.py` imports `console/redact.py` — the single masking implementation,
  so the egress guard can never drift from the rest of the project. If it can't
  import, the server fails **closed** (it won't start and can't leak), never open.
- `threat_intel_lookup` reads the sibling `threat_intel/` offline path.

So a **standalone** install outside the repo (e.g. bare `uvx itsoc-mcp`) cannot
currently run — this is stated plainly rather than hidden. A true standalone
release would require vendoring `console/redact.py` into the package (and guarding
`threat_intel_lookup`), which is a deliberate, human-gated decision; see
[`PUBLISHING.md`](PUBLISHING.md).

## License

MIT — see the repository's top-level [`LICENSE`](../LICENSE).
