# Share your logs safely

You want us to validate the analyzer against your real logs — but your logs
contain things that must not leave your network: IP addresses, usernames,
hostnames. This flow lets you run the full analysis **on your own machine**
and send back only a **redacted findings report**. Your raw logs never move.

## One command

```bash
python3 scripts/intake.py /path/to/your.log
```

That's it. It writes an `intake_out/` directory next to where you ran it.

## What happens (all locally)

1. **Analyze.** The deterministic rule engine reads your log and produces
   findings with severities. This is the rules-only path: **no model call, no
   network I/O of any kind**. You can run it with your network cable unplugged.
2. **Redact.** Every log-derived string in the report is passed through the
   project's single redaction choke point (`console/redact.py`), which masks:
   - **IPv4 and IPv6 addresses** → `[IP-1]`, `[IP-2]`, …
   - **Usernames** (auth/sshd/PAM vocabularies, plus every username the rules
     extracted) → `[USER-1]`, …
   - **Hostnames** (every host the parser saw in your log) → `[HOST-1]`, …

   Placeholders are deterministic within the report: `[IP-1]` always means the
   same address, so "the same source hit three hosts" stays visible without
   exposing the address. Masking is deliberately conservative — it may
   occasionally mask a non-secret token; it never widens what is shared.
3. **Report.** Two shareable artifacts are written from the redacted data.

## What you get

| File | Contents | Share? |
| --- | --- | --- |
| `intake_out/report.local.json` | Full unredacted analysis | **No — keep on your machine** |
| `intake_out/report.local.md` | Full unredacted report | **No — keep on your machine** |
| `intake_out/report.redacted.md` | Masked findings table | **Yes** |
| `intake_out/report.redacted.html` | Masked, self-contained review console (opens in any browser, makes zero network requests) | **Yes** |

## Honesty guarantees

- If your log format isn't recognized, the report says **"FORMAT NOT
  RECOGNIZED — 0 lines parsed"** and explicitly states it is **not** an
  all-clear. Same for an empty file. You will never receive a fake clean
  report, and no finding is ever fabricated.
- Severities come from deterministic rules only. Nothing in this flow asks a
  model anything, so there is nothing to hallucinate.
- The report records the sha256 of your input and of the (frozen) detector, so
  a finding can always be traced back to the exact bytes that produced it.

## Sending the report back

Before sending `report.redacted.md` (or `.html`), skim it once — you know your
environment best, and the placeholder counts in the header tell you exactly
how many IPs/usernames/hostnames were masked. Then email it or drop it in the
shared channel. If a finding needs deeper investigation, we'll tell you which
`[IP-n]` / `[HOST-n]` placeholder matters and *you* look up what it maps to on
your side — the mapping never leaves your machine.
