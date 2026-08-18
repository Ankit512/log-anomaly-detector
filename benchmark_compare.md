# Compare-mode benchmark — deterministic rules vs. the model alone

_6 inputs · 21 chunks · chunk size 25 lines · llama3.1:8b · temperature 0 · unprimed pass cached by chunk hash_

Measures how often the rules rate a finding **above** what the same model rates it with no rules, no pre-flagged anomalies and no instruction to defer. A chunk the model could not answer in schema is **UNKNOWN** and is excluded from the rate — an absence of evidence is not a miss, and counting it as one would inflate the result.

## Headline

- **Under-rated rate (excluding UNKNOWN): 21%** — 3 of 14 comparable findings
- **Degraded chunks: 0%** — 0 of 21 chunks gave no usable answer
- Comparable coverage: 14 of 14 rule findings had a usable model verdict

## Totals

| Outcome | Count |
|---|---|
| Rule **above** model — under-rated | **3** |
| Rule == model — agree | 7 |
| Rule **below** model — over-rated | 4 |
| UNKNOWN — no usable model answer | 0 |
| **Total rule findings** | 14 |

## Per input

| Input | Chunks | Degraded | Findings | under-rated | agree | over-rated | UNKNOWN |
|---|---|---|---|---|---|---|---|
| sample-2.log (synthetic, 19 lines) | 1 | 0 | 4 | 2 | 1 | 1 | 0 |
| OpenSSH_2k [lines 1–100] | 4 | 0 | 2 | 0 | 1 | 1 | 0 |
| OpenSSH_2k [lines 101–200] | 4 | 0 | 4 | 0 | 2 | 2 | 0 |
| OpenSSH_2k [lines 201–300] | 4 | 0 | 1 | 0 | 1 | 0 | 0 |
| Linux_2k [lines 1–100] | 4 | 0 | 1 | 1 | 0 | 0 | 0 |
| Linux_2k [lines 101–200] | 4 | 0 | 2 | 0 | 2 | 0 | 0 |

## Chunk status — the 8B schema-reliability signal

| Status | Chunks | Meaning |
|---|---|---|
| `ok` | 21 | valid schema on the first try |

## Every rule finding

| Input | Rule | LLM alone | Delta | Rule id |
|---|---|---|---|---|
| Linux_2k [lines 1–100] | HIGH | MEDIUM | under-rated | `auth_bruteforce` |
| sample-2.log (synthetic, 19 lines) | CRITICAL | HIGH | under-rated | `auth_bruteforce_success` |
| sample-2.log (synthetic, 19 lines) | HIGH | LOW | under-rated | `suspicious_outbound` |
| OpenSSH_2k [lines 101–200] | MEDIUM | HIGH | over-rated | `possible_break_in` |
| OpenSSH_2k [lines 101–200] | MEDIUM | HIGH | over-rated | `possible_break_in` |
| OpenSSH_2k [lines 1–100] | MEDIUM | HIGH | over-rated | `possible_break_in` |
| sample-2.log (synthetic, 19 lines) | MEDIUM | HIGH | over-rated | `error_rate_spike` |
| Linux_2k [lines 101–200] | HIGH | HIGH | agree | `auth_bruteforce` |
| Linux_2k [lines 101–200] | HIGH | HIGH | agree | `auth_bruteforce` |
| OpenSSH_2k [lines 101–200] | HIGH | HIGH | agree | `auth_bruteforce` |
| OpenSSH_2k [lines 101–200] | HIGH | HIGH | agree | `auth_bruteforce` |
| OpenSSH_2k [lines 1–100] | HIGH | HIGH | agree | `auth_bruteforce` |
| OpenSSH_2k [lines 201–300] | HIGH | HIGH | agree | `auth_bruteforce` |
| sample-2.log (synthetic, 19 lines) | CRITICAL | CRITICAL | agree | `critical_service_event` |

## Reading this

At 25-line chunks the model stayed in schema on every chunk, so coverage is complete and the rate is measured, not estimated. That is itself the finding about chunk size: the schema drift seen at 100-line chunks disappears here.

The under-rated rate is what the console's headline pill counts. It is **not** a claim that the rules are right and the model is wrong — over-rated rows are cases where the model was more alarmed than the rules. What the rate measures is how often a rules-first pipeline surfaces something at a higher severity than the model alone would have.

