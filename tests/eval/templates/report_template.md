<!--
REPORT TEMPLATE — validate_real.py emits exactly this shape (see
tests/eval/reports/Linux_bruteforce_slice.report.md for a FILLED example).
Fill by running:
  python3 tests/eval/validate_real.py --log <LOG> --labels <LABELS> --report <OUT>.md
Do NOT hand-edit the numbers: they must come from a real label comparison.
Placeholders in <ANGLE BRACKETS>.
-->
# Detection Validation Report — `<LOG FILE NAME>`

- **Log file:** `<path/to/log>`
- **Labels:** ground-truth `expected` findings, hand-labeled
- **Label note:** <who labeled it, when, and how ground truth was decided>
- **Detector:** frozen `anomaly_detector.py` (sha256 43f0560f…312d05); severity is rule-owned, never guessed here

## Parse coverage

```
format='<FORMAT>'  parsed=<P>/<TOTAL>  unparsed=<U> (<PCT>% unrecognized)
```
<!-- If parsed == 0, an honest UNRECOGNIZED-FORMAT banner appears here instead of
     an all-clear, and precision is reported n/a. -->

## Scorecard

| metric | value |
|---|---|
| true positives | <TP> |
| false positives | <FP> |
| false negatives (missed) | <FN> |
| precision | <0.000 or n/a> |
| recall | <0.000 or n/a> |
| F1 | <0.000 or n/a> |

## False positives (detector fired, not labeled)

<!-- each: `<rule_id>` **<severity>** `<entity>` — <evidence> ; or _None._ -->

## Missed detections / false negatives (labeled, detector silent)

<!-- each: `<rule_id>` **<severity>** `<entity>` (lines <n>) — <note> ; or _None._ -->

## Severity mismatches (right attack + entity, wrong severity)

<!-- each: `<rule_id>` `<entity>` — detector said **<sev>**, labeled **<sev>** ; or _None._
     Severity is rule-owned: a mismatch is a finding to review, not a harness bug. -->

## Confirmed detections (true positives)

<!-- each: `<rule_id>` **<severity>** `<entity>` — <evidence> ; or _None._ -->
