# Contributing

A short working agreement so a second developer doesn't accidentally break the conventions
this project depends on. New here? Read [`GUIDE.md`](GUIDE.md) for the plain-language overview
and [`PROJECT_HANDOFF.md`](PROJECT_HANDOFF.md) for the technical picture.

## Golden rules

1. **One branch per change.** Work on a topic branch (e.g. `t5-json-format`), not directly on
   `main`. Keep history linear where possible.

2. **Run the tests before every commit — they must be green.**
   ```bash
   python3 tests/eval/run_eval.py            # expect: 15/15, exit 0
   python3 threat_intel/test_threat_intel.py # expect: exit 0
   python3 console/test_console.py           # console render smoke test, exit 0
   ```
   CI runs all three on every push and pull request, headless (no network, no model). Don't push red.

3. **The detector is effectively frozen.** `anomaly_detector.py` is the validated core; the
   pristine original is preserved in `archive/anomaly_detector_original.py`. Do **not** edit
   it casually. Add support for new log formats as **sibling modules** (`normalize.py` for the
   envelope, `rules_syslog.py` for vocabulary), feeding the detector via the record dict — not
   by changing its rules. If a change to the detector is genuinely unavoidable (as the
   sliding-window severity fix was), archive the current version first, re-run the full test
   suite, and note the new file hash.

4. **If you change a severity, update the eval corpus in the same commit.** The corpus
   (`tests/eval/manifest.json`) documents *current* behaviour, so any deliberate severity
   change (e.g. the parked disk-≥90% decision, or `threat_intel/severity_for()`) will turn CI
   red until the manifest is updated to match. That friction is intentional — it makes every
   severity change visible and reviewed.

5. **Stay local and read-only.** No code that changes systems, and nothing that sends log data
   to a third party. Enrichment (like threat-intel) pulls data *in* and matches locally;
   offline mode is the default. Any future action-taking must be gated behind explicit human
   approval.

6. **Never commit secrets.** `.env` is gitignored — keep it that way. Only `.env.example`
   (placeholder values) is tracked. No keys, tokens, or passwords in code, config, or logs.

7. **Honest surfaces.** This is an audit tool; the UI must never claim more than it can prove.
   Show computed **integrity** hashes, never a "signature valid" badge for an unsigned run.
   If `--compare` wasn't run, show "compare not run," never a fake "0 under-rated." Degraded
   model chunks are `UNKNOWN`, never counted as a miss. The console and `report.json` stay
   fully local — nothing phones home (a fonts CDN counts).

8. **Additive layers.** The console (`console/`), compare mode (`compare.py`), rule context
   (`rule_context.py`), and threat-intel (`threat_intel/`) are all *additive* — they read the
   analyzer's output and never change authoritative, rule-owned severities. Keep it that way.

## Adding a new log format (the common task)

1. Get a **real sample** of the format first — don't build against a guess.
2. Add envelope parsing to `normalize.py` and any vocabulary mapping to `rules_syslog.py`.
   Leave `anomaly_detector.py` alone; the detector consumes the normalized record dict.
3. Add labeled cases to `tests/eval/` (a positive detection, a negative/near-miss control,
   and a format-equivalence check against an existing format) and wire them into
   `manifest.json`.
4. Run `run_eval.py` — green means you didn't regress anything.

## Dependencies

The core pipeline and offline threat-intel are **standard-library only** — no `pip install`
needed. External packages (`taxii2client`, `stix2`) are required *only* for live TAXII pulls
and live in `threat_intel/requirements-taxii.txt`, kept separate on purpose so CI proves the
offline path works without them.

## Security principles (non-negotiable)

Data stays local · read-only, no automated actions · human approval before any future write ·
certificate/token authentication only (note: live TAXII's current `--taxii-password` flag must
be replaced with cert/token before it is enabled) · secrets never committed.
