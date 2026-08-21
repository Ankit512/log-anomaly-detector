# itsoc_mcp — a read-only MCP server over the local analysis backend

<!-- The line below is the MCP Registry PyPI ownership marker (must ship in the
     PyPI long-description). Keep it identical to `name` in itsoc_mcp/server.json. -->
mcp-name: io.github.Ankit512/itsoc-mcp

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

## Standalone install (`uvx` / `pipx`)

`pyproject.toml` builds an `itsoc-mcp` distribution with an `itsoc-mcp` console
script (`itsoc_mcp.server:main`) and pins `mcp>=1.0,<2` — MCP clients speak the
stable 1.x API; mcp 2.0 changed the server API. The package is **self-contained**:
designed to run with no repo checkout.

```sh
uvx itsoc-mcp        # or: pipx run itsoc-mcp   (the backend must still be running)
```

Two honesty points, stated plainly:

- **The egress guard is never weakened standalone.** Redaction has a single source
  of truth — `console/redact.py` — used whenever the repo is importable. In a bare
  install it falls back to a **verbatim vendored mirror** (`_redact_vendored.py`)
  that masks identically (redact-by-default; raw only with
  `ITSOC_MCP_TRUSTED_LOCAL=1`). A drift-guard test asserts the two never diverge,
  so the vendored copy can never silently mask *less*. `redaction.redact_source()`
  reports which is active. If neither could load, the module fails to import rather
  than pass text through — it fails **closed**, never open.
- **`threat_intel_lookup` needs the repo.** Its offline STIX→MITRE path reuses the
  repo's sibling `threat_intel/` package, which a bare install does not ship. In a
  standalone install that one tool **fails closed** with an honest
  "offline threat-intel unavailable … NOT a clean verdict / not an all-clear"
  message — never a fabricated match or a fake all-clear. Run from the repo
  (`python -m itsoc_mcp`) to use offline threat-intel. Every other tool is a client
  of the backend API and works identically standalone or in-repo.

Standalone means *no repo checkout is needed for the MCP package* — the backend
(`python3 console/serve.py`) still runs separately and must be reachable at
`ITSOC_BASE_URL`.

## License

MIT — see the repository's top-level [`LICENSE`](../LICENSE).

## License

MIT — see the repository's top-level [`LICENSE`](../LICENSE).
