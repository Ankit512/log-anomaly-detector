# Real-log validation harness

`validate_real.py` measures the **frozen detector's** detection quality on a
**real log** against a **hand-labeled ground-truth** file. It complements
`run_eval.py`:

| | `run_eval.py` | `validate_real.py` |
|---|---|---|
| ground truth | synthetic corpus with injected attacks | **you hand-label a real log** |
| input | `manifest.json` cases | `--log` + `--labels` |
| output | pass/fail scorecard | precision/recall/F1 + FP list + missed-detection list + **parse coverage** |
| verdicts | none — runs the frozen detector | none — runs the same frozen detector |

The harness computes **no verdicts of its own.** It runs the existing
deterministic path (`normalize` → `rules_syslog` → `anomaly_detector.detect`,
identical to `run_eval.analyze`) and **scores that output** against your labels.
Severity stays **rule-owned** — the harness reads the detector's severity and
never guesses one.

## Why this exists

Before real production logs arrive, the harness is built and self-tested on the
existing sample logs so that validation is **instant** the moment real data
lands: drop the log in, hand-label the attacks you can see, run one command.

## How to run

```bash
# Score a log against labels, print the scorecard:
python3 tests/eval/validate_real.py \
  --log tests/eval/fixtures/Linux_bruteforce_slice.log \
  --labels tests/eval/labels/Linux_bruteforce_slice.labels.json

# Also write a markdown report:
python3 tests/eval/validate_real.py --log <LOG> --labels <LABELS> --report out.md

# Machine-readable scorecard:
python3 tests/eval/validate_real.py --log <LOG> --labels <LABELS> --json

# Prove the scorer + FP/FN/severity rendering on synthetic data (no real log needed):
python3 tests/eval/validate_real.py --selftest
```

**Exit codes:** `0` normal (even when the detector disagrees with labels — that
is a *result*, not a harness error); `2` only on a hard failure — the log's
format is unrecognized (**0 lines parsed**) while labels are present, so scoring
is meaningless. This lets CI gate on "the harness could actually read the log"
without conflating it with "the detector missed something".

## Ground-truth label format

A small JSON file. **Dead simple to hand-label:** read the raw log, and for each
attack you can see, write one `expected` entry.

```json
{
  "log": "tests/eval/fixtures/Linux_bruteforce_slice.log",
  "note": "who labeled it, when, and how you decided ground truth",
  "expected": [
    {
      "rule_id": "auth_bruteforce",
      "severity": "high",
      "entity": "218.188.2.4",
      "evidence_lines": [1, 42],
      "note": "14 failed passwords for 'unknown'"
    }
  ]
}
```

| field | required | meaning |
|---|---|---|
| `rule_id` | ✅ | the detector `type` you expect (e.g. `auth_bruteforce`, `possible_break_in`, `error_rate_spike`, `critical_service_event`) |
| `severity` | ✅ | your **expected** rule-owned severity (`critical`/`high`/`medium`/`low`/`info`) |
| `entity` | ✅* | the principal the finding is about — the attacker IP for auth/network, the host for resource findings. `null`/omit if the finding has no entity. |
| `evidence_lines` | optional | line numbers in the log that justify the label — **human traceability only, not scored** |
| `note` | optional | free text — not scored |

**Scoring unit = `(rule_id, severity, entity)`.** The detector emits
**correlated** findings (one per attacker/entity), not per-line verdicts, so the
finding — not the line — is the unit that can be scored. `evidence_lines`/`note`
are for a human reading the report.

- **True positive:** a labeled `(rule_id, severity, entity)` the detector also produced.
- **False positive:** the detector produced it, you did **not** label it.
- **False negative (missed):** you labeled it, the detector stayed **silent**.
- **Severity mismatch:** same `(rule_id, entity)` on both sides, different
  `severity`. Surfaced separately so one real attack is not misread as an
  unrelated FP + FN. Severity is rule-owned, so a mismatch is a **finding to
  review** (rule vs analyst disagree on criticality), never a harness bug.

### Labeling tip

To label brute-force truthfully and independently of the detector, count auth
failures per source straight from the raw log, e.g.:

```bash
grep -nE "Failed password|authentication failure|Invalid user" <LOG> \
  | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort | uniq -c | sort -rn
```

A source with many rapid failures is a brute-force attack; a lone stray failure
is benign — leave it **unlabeled** so precision (no-false-fire) is actually
tested.

## Honesty guarantees

- **Rule-owned severity.** The harness never keyword-guesses severity; it reads
  what the frozen detector assigned.
- **Honest unrecognized format.** `parsed == 0` prints an explicit
  `UNRECOGNIZED FORMAT — 0 lines parsed … NOT an all-clear` banner and reports
  `precision = n/a`. Never a fake green.
- **No fabricated metrics.** A value that cannot be computed prints `n/a`, not a
  guess. Every precision/recall/F1 number comes from a real label comparison.
- **Frozen detector.** `shasum -a 256 anomaly_detector.py` must equal
  `43f0560f2a81d52a9b8909d4c0f3a537ef2059b343ea48acc7dba59b38312d05`.

## Files

- `validate_real.py` — the harness (score, report, `--selftest`).
- `templates/report_template.md` — the report shape the harness fills.
- `fixtures/Linux_bruteforce_slice.log` — a verbatim 250-line slice of
  `samples/Linux_2k.log` (real data, unmodified).
- `labels/Linux_bruteforce_slice.labels.json` — the hand-labeled ground truth.
- `reports/Linux_bruteforce_slice.report.md` — the **filled example** report.
