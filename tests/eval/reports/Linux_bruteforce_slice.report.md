# Detection Validation Report — `Linux_bruteforce_slice.log`

- **Log file:** `tests/eval/fixtures/Linux_bruteforce_slice.log`
- **Labels:** ground-truth `expected` findings, hand-labeled
- **Label note:** Hand-labeled 2026-08-20 by dwight. Attacker IPs and failure counts were read directly from the raw 'authentication failure'/'Failed password' lines in the slice (NOT copied from detector output). An analyst calls a source with many rapid auth failures a brute-force attack; a single stray failure is benign and is deliberately left unlabeled so precision (no-false-fire) is actually exercised.
- **Detector:** frozen `anomaly_detector.py` (sha256 43f0560f…312d05); severity is rule-owned, never guessed here

## Parse coverage

```
format='rfc3164'  parsed=250/250  unparsed=0 (0.0% unrecognized)
```

## Scorecard

| metric | value |
|---|---|
| true positives | 3 |
| false positives | 0 |
| false negatives (missed) | 0 |
| precision | 1.000 |
| recall | 1.000 |
| F1 | 1.000 |

## False positives (detector fired, not labeled)

_None._

## Missed detections / false negatives (labeled, detector silent)

_None._

## Severity mismatches (right attack + entity, wrong severity)

_None._

## Confirmed detections (true positives)

- `auth_bruteforce` **high** `217.60.212.66` — 6x auth failed for 'guest' from 217.60.212.66 (lines 193-198)
- `auth_bruteforce` **high** `218.188.2.4` — 14x auth failed for 'unknown' from 218.188.2.4 (lines 1-42)
- `auth_bruteforce` **high** `65.166.159.14` — 10x auth failed for 'unknown' from 65.166.159.14 (lines 169-187)
