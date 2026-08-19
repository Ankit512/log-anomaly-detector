# A Plain-Language Guide to This Project

*What it is, what it does, and how it works — no technical background needed.*

## In one paragraph

This project is a smart assistant that watches over the records computers keep — called
“logs” — and automatically points out signs of trouble, such as someone trying to break in
or a system starting to fail. It reads through thousands of lines that no human has time to
check, highlights the ones that matter, ranks how serious each one is, and explains every
finding in plain English. It runs entirely on your own computer, so the data it reads is
never sent anywhere.

## The problem it solves

Every computer, server, firewall, and network device keeps a running diary of what it is
doing: every login, every request, every error, every connection. These diaries are called
logs. A busy system can write thousands of lines every hour.

Buried in that flood are the handful of lines that actually matter — the repeated failed
logins that signal an attack, the error that means a service is about to go down, the
connection to a suspicious address. Finding them by hand is like searching for one specific
sentence in a library that adds a new book every minute. People miss things not because they
are careless, but because there is simply too much to read.

This tool does that reading for you — tirelessly, consistently, and fast.

## What it does, and how it works

The tool uses two “workers” with very different strengths, and the design is careful about
which one is trusted for what.

**The Detective** is a set of fixed, reliable rules that already know what trouble looks
like: five failed logins from the same place within two minutes is a break-in attempt; a
connection to a known-bad address is suspicious; a disk that is 95% full is a warning sign.
The Detective is consistent and never exaggerates — it decides *how serious* each finding is.

**The Explainer** is a local AI model. It reads the Detective’s findings and writes them up
in clear, plain English, and it also notices smaller oddities the fixed rules don’t cover.
But it never decides severity — it only describes.

> **Why split the work this way?** Fixed rules are dependable about how serious something is,
> but clumsy at explaining. AI is wonderful at language but can be inconsistent and
> occasionally over- or under-reacts. So we let each do only what it is best at: the rules
> judge, the AI explains. That combination catches things either one alone would miss.

The result is a report that, for each problem, tells you what happened, who or what was
involved, how serious it is, and why — in language anyone can read.

## The kinds of trouble it catches

| Sign of trouble | What it means in plain terms |
|---|---|
| Brute-force attack | Someone guessing passwords over and over to force their way in. |
| Account compromise | The guessing worked — a break-in actually succeeded. The most serious case. |
| Suspicious connection | One of your machines talking to an address known for hacking. |
| Scanning / probing | An outsider quietly poking at your systems, looking for a way in. |
| Service failure | A system overloaded, timing out, or crashing. |
| Disk filling up | Running low on storage — which, left alone, can take systems down. |

## A real example

Here is an actual example from a small test log. Hidden inside twenty ordinary-looking lines
were three separate problems:

- **The break-in.** A stranger at address 203.0.113.44 tried to log in as “admin” and failed
  seven times in a row — then succeeded. The tool flags this as CRITICAL: not just an
  attempted break-in, but a likely successful one.
- **The failure.** A server ran out of its database connections and started failing requests
  — a service outage in the making. Flagged CRITICAL.
- **The suspicious connection.** One machine tried to reach an outside address on a channel
  commonly used by attackers. Flagged HIGH.

A person skimming those twenty lines could easily miss the pattern — especially that the
failed logins were followed by a success. The tool caught all three and ranked them, so the
most urgent one stands out.

## Why it is built the way it is

Three deliberate choices shape the whole project, and they are all about trust and safety:

- **It stays local.** It runs on your own computer using a free, open AI model. Your logs —
  which can contain sensitive information — are never uploaded to any outside company.
  Privacy is built in, not bolted on.
- **It is read-only.** The tool only watches and reports. It never changes anything or acts
  on its own — think smoke detector, not fire sprinkler. If it is ever given the power to act
  (like blocking an attacker), that will always require a person to approve it first.
- **It needs no training.** It doesn’t need to be “trained” on your data or sent away to
  learn. It works out of the box using clear rules plus a general AI model, which keeps it
  simple, private, and predictable.

## Where the project stands today

The work is planned in three phases. The first two are complete, and the third is well underway:

- **Phase 1** — reading a log and summarizing it with the local AI. Done.
- **Phase 2** — spotting anomalies with the rules-plus-AI approach above. Done, and working
  on real-world logs (not just neat test samples), with an automated test suite that guards
  every future change against accidental breakage.
- **Phase 3** — a fuller operations platform. Well underway: there is now a proper
  **security dashboard** you open in a browser (details below), it reads several real-world
  log styles (ordinary system logs, secure-shell logs, a popular security-product export, and
  Android phone logs), and an optional step recognizes known-bad addresses and maps them to
  known attacker techniques. The rest (running continuously and — only with human approval —
  helping fix problems) is still planned.

There are two ways to look at the results, both on your own machine, nothing uploaded:

- **A simple review page** — one command turns a log into a tidy page of findings, ranked by
  seriousness, each with the exact evidence and a plain-English explanation. It can also show,
  side by side, what the AI *alone* would have said versus what the reliable rules concluded.
- **A full security dashboard** — a modern control-room screen with several sections: an
  **Overview** (the big picture — how many alerts, how serious, over what time), **Alerts**
  (every finding), **Incidents** (related findings grouped into one event you can walk through
  its lifecycle — new, acknowledged, investigating, resolved), **Assets** (which machines and
  user accounts actually showed up, and which are at risk), **Threat Intel** (known-bad
  addresses and attacker techniques), and **Reports** (save or download the whole run as a
  file — a spreadsheet, a web page, or a data file — to share or archive).

Every panel follows one rule: show real information drawn from the log, or honestly say there
is nothing yet — it never invents a number to fill a space.

In short: the core — reliably spotting and explaining trouble in real logs — is built,
tested, documented, and now has both a quick review page and a full dashboard to work in.

## The bigger vision

The long-term goal is a complete operations assistant for the teams that keep data centers,
networks, and security running. Beyond spotting problems, a mature version would pull in
helpful context (is this a critical production server or a test machine? is this address
already known to be malicious?), explain the likely root cause, and — only ever with human
approval — help fix the problem. Every future step is designed around the same safety
principles: sensitive data stays in-house, and nothing is ever changed automatically without
a person signing off.

## A few terms, defined simply

| Term | Plain meaning |
|---|---|
| Log | A computer’s running diary of everything it does. |
| Anomaly | Something out of the ordinary that may signal a problem. |
| Brute-force | Repeatedly guessing passwords to break into an account. |
| Severity | How serious a finding is — e.g. Critical, High, Medium. |
| False positive | A false alarm — flagging something that was actually harmless. |
| False negative | A miss — failing to flag something that was real. |
| Local AI model | AI that runs on your own computer instead of a company’s servers. |
| Read-only | Able to look and report, but never to change or act. |

---

*For how to install and run it, see [`README.md`](README.md). For the full technical picture
— architecture, build history, and roadmap — see [`PROJECT_HANDOFF.md`](PROJECT_HANDOFF.md).*
