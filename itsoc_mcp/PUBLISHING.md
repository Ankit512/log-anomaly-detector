# Publishing `itsoc-mcp` — DRAFT (human-gated)

This is a **draft** describing how to publish. Nothing here has been run. **Do
not** run `twine upload`, `mcp-publisher login`, `mcp-publisher publish`, push to
any external repo, or open any PR without a human decision — those steps are
intentionally left to a person.

> **The official path is the MCP Registry (`registry.modelcontextprotocol.io`).**
> It is metadata-only and driven by the `mcp-publisher` CLI plus a `server.json`
> manifest (see [`server.json`](server.json), validated against the current
> `2025-12-11` schema). The old "open a PR against `modelcontextprotocol/servers`"
> path is **obsolete** — that repo redirects to the official registry. Do not open
> a servers-repo PR.

## Server identity

- **Registry name:** `io.github.Ankit512/itsoc-mcp` (GitHub-namespaced; matches the
  `name` in `server.json` **and** the `mcp-name:` marker in the PyPI README).
- **PyPI package:** `itsoc-mcp`
- **Version:** `0.1.0` (must match across `pyproject.toml`, `server.json`, and the
  PyPI upload on every release).
- **One-line description:** Read-only MCP server over a local log-analysis
  backend; a client that computes no verdicts.
- **Homepage:** https://github.com/Ankit512/log-anomaly-detector
- **License:** MIT · **Transport:** stdio
- **Tools (all read-only):** `analyze_log`, `list_runs`, `get_findings`,
  `get_evidence`, `explain_finding`, `export_run`, `threat_intel_lookup`

## Publish flow (human-run, in order)

Ownership of the `io.github.Ankit512/*` namespace is proven two ways: the
`mcp-name: io.github.Ankit512/itsoc-mcp` marker that ships in the PyPI
long-description (already in [`README.md`](README.md)), and a GitHub OAuth login.

1. **PyPI upload FIRST** (the registry only references an already-published
   package). From `itsoc_mcp/`, with the maintainer's PyPI token:

   ```sh
   python -m build                 # -> dist/itsoc_mcp-0.1.0-{whl,tar.gz}
   twine upload dist/*             # human's PyPI token
   ```

   The build embeds the `mcp-name:` marker in the package long-description — this
   is what the registry checks to verify PyPI ownership.

2. **Authenticate to the registry** (interactive GitHub OAuth; proves you own the
   `io.github.Ankit512` namespace):

   ```sh
   mcp-publisher login github
   ```

3. **Publish the manifest** (metadata-only; points at the PyPI package from step 1):

   ```sh
   mcp-publisher publish          # reads ./server.json
   ```

Run steps 2–3 from the directory containing `server.json` (`itsoc_mcp/`). On each
new release, bump the version in `pyproject.toml` **and** `server.json` together,
re-upload to PyPI, then `mcp-publisher publish` again.

## Install (once published)

```sh
uvx itsoc-mcp        # or: pipx run itsoc-mcp   (the backend must still be running)
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

## Pre-publish checklist (for the human)

- [ ] Confirm the LICENSE copyright holder name (currently "Ankit Kumar").
- [ ] Versions match: `pyproject.toml` == `server.json` == the version uploaded to PyPI.
- [ ] `server.json` validates against the current schema (see the drift below).
- [ ] `python -m build` from `itsoc_mcp/`; confirm the `mcp-name:` marker is in the
      built long-description (`grep mcp-name` inside `dist/*` METADATA/PKG-INFO).
- [ ] `python3 itsoc_mcp/test_mcp.py` green (includes the redaction drift-guard);
      `python3 console/test_console.py` green.
- [ ] Confirmed: installs + runs in a clean out-of-repo venv, redaction masks by
      default via the vendored mirror, `threat_intel_lookup` fails closed.
- [ ] Only then, in order: `twine upload` → `mcp-publisher login github` →
      `mcp-publisher publish`.

> **Schema note:** the registry schema is versioned by date
> (`https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json`).
> If the CLI reports a schema mismatch on publish, re-scaffold with
> `mcp-publisher init` (no login required) and re-apply these field values.
